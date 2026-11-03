#!/usr/bin/env python3
"""Owner-run, offline extraction from their own Geely Android APKs.

No APK, vendor key, encrypted vendor blob, account data or network client is
included. Android 1.1.1 and the validated ARM64 1.3.0 (10300) are supported.
This script never connects to a phone, signs in or contacts a vehicle.
"""
import argparse
import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

from _apk130 import UnsupportedBuildError, regional_dex, verify_member


def _select_build(manifest):
    if manifest is None or manifest.get("package") != "com.geely.global":
        raise UnsupportedBuildError()
    prefix = "{http://schemas.android.com/apk/res/android}"
    version = manifest.get(prefix + "versionName")
    if version == "1.1.1":
        return version
    if version == "1.3.0" and manifest.get(prefix + "versionCode") == "10300":
        return version
    raise UnsupportedBuildError()


def _read_member(apk, name, limit=128 * 1024 * 1024):
    info = apk.getinfo(name)
    if info.file_size > limit:
        raise ValueError("APK member exceeds the supported size")
    return apk.read(info)


def extract_keys(base_path, arm64_path=None):
    # Optional dependencies are needed only for this manual tool, never in HA.
    from loguru import logger
    logger.remove()
    from androguard.core.axml import AXMLPrinter
    from androguard.core.dex import DEX
    from asn1crypto import core
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    from elftools.elf.elffile import ELFFile
    from _native import Native

    with zipfile.ZipFile(base_path) as apk:
        manifest = AXMLPrinter(_read_member(apk, "AndroidManifest.xml")).get_xml_obj()
        version = _select_build(manifest)
        dex_bytes = _read_member(apk, "classes7.dex" if version == "1.1.1" else "classes.dex")
    with zipfile.ZipFile(arm64_path or base_path) as apk:
        env_bytes = _read_member(apk, "lib/arm64-v8a/libenv.so")
        ca_bytes = _read_member(apk, "lib/arm64-v8a/libiwallca.so")
    if version == "1.3.0":
        verify_member("libenv.so", env_bytes)
        verify_member("libiwallca.so", ca_bytes)
        dex_bytes = regional_dex(dex_bytes)
    dex = DEX(dex_bytes)

    # Execute the environment initializer and getters in isolated emulated
    # memory. Unknown imports are rejected; no library is loaded into the host.
    with tempfile.TemporaryDirectory(prefix="geely-offline-") as root:
        lib = Path(root) / "libenv.so"
        lib.write_bytes(env_bytes)
        if version == "1.3.0":
            from _native130 import RegisteredNative
            native = RegisteredNative(lib)
            native.initialize()
            methods = native.registered
        else:
            native = Native(lib)
            prefix = "Java_com_zeekr_env_ServerUtils_"
            methods = {name: prefix + name for name in (
                "upDateNativeEnvironment", "getNativeHost",
                "getNativeApplicationId", "getNativeSecret",
            )}
        # The getters read global state set by this initializer; they take no
        # region arguments themselves. PROD=3, OVERSEAS=3 in this APK.
        native.call(methods["upDateNativeEnvironment"], 3, 3)
        host = native.cstr(native.call(methods["getNativeHost"])).decode()
        if host.rstrip("/") != "gateway-pub-azure.zeekr.eu":
            raise ValueError("The APK does not select the expected European service")
        values = {
            "hmac_access_key": native.cstr(native.call(methods["getNativeApplicationId"])).decode(),
            "hmac_secret": (native.signing_key() if version == "1.3.0" else
                            native.cstr(native.call(methods["getNativeSecret"])).decode()),
        }

    # Interpret only constant construction of the regional key table.
    blobs = {}
    table_class, tuple_class, pair_class = (
        ("Ltj/i;", "Lpk/x0;", "Lpk/y0;") if version == "1.1.1" else
        ("Lvj/i;", "Lrk/x0;", "Lrk/y0;")
    )
    for cls in dex.get_classes():
        if cls.get_name() != table_class:
            continue
        for method in cls.get_methods():
            if method.get_name() not in ("d", "e", "f"):
                continue
            regs, result = {}, None
            for ins in method.get_instructions():
                name, text = ins.get_name(), ins.get_output()
                r = [int(v) for v in re.findall(r"\bv(\d+)\b", text)]
                if name == "sget-object":
                    regs[r[0]] = text.split("->")[1].split(" ")[0]
                elif name == "new-instance":
                    regs[r[0]] = {}
                elif name.startswith("const-string"):
                    regs[r[0]] = ins.get_string()
                elif name == "move-result-object":
                    regs[r[0]] = result
                elif name.startswith("move-object"):
                    regs[r[0]] = regs[r[1]]
                elif name.startswith("invoke-virtual") and "->getValue()" in text:
                    result = regs[r[0]]
                elif name == "invoke-direct" and tuple_class + "-><init>" in text:
                    regs[r[0]]["tuple"] = [regs[n] for n in r[1:]]
                elif name == "invoke-static" and pair_class + "->a(" in text:
                    result = [regs[r[0]]["tuple"], regs[r[1]]]
                    if result[0] == ["GEELY", "EU", "PROD"]:
                        blobs[method.get_name()] = result[1]
    if set(blobs) != {"d", "e", "f"}:
        raise ValueError("The APK key table does not match the supported build")

    source = io.BytesIO(ca_bytes)
    elf = ELFFile(source)

    def read(address, size):
        for segment in elf.iter_segments():
            if (segment["p_vaddr"] <= address
                    and address + size <= segment["p_vaddr"] + segment["p_filesz"]):
                source.seek(segment["p_offset"] + address - segment["p_vaddr"])
                return source.read(size)
        raise ValueError("Unsupported library layout")

    # Every byte of vendor material is read from the owner's APK, not this repo.
    salt, data = read(0xd8aa1, 32), read(0x3f5eec, 329)
    digest = hashlib.new("sm3", salt + b"\x01\x00").digest()
    aes_key = bytes(data[(byte % 6) * 32 + i] for i, byte in enumerate(digest))
    private_key = load_der_private_key(
        AESGCM(aes_key).decrypt(aes_key[:12], data[192:], aes_key[:4]), None
    )

    def decode(blob):
        sequence = core.Sequence.load(base64.b64decode(blob, validate=True))
        ephemeral, ciphertext, tag = [sequence[i].native for i in range(3)]
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral)
        shared = private_key.exchange(ec.ECDH(), public_key)
        length = len(ciphertext)
        material = b"".join(
            hashlib.sha256(shared + counter.to_bytes(4, "big")).digest()
            for counter in range(1, (length + 63) // 32 + 1)
        )[:length + 32]
        expected = hmac.new(material[length:], ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise ValueError("APK key authentication failed")
        return bytes(a ^ b for a, b in zip(material, ciphertext))

    values.update(
        snc_secret=decode(blobs["f"]).decode(),
        vin_key_hex=decode(blobs["e"]).hex(),
        vin_iv_hex=decode(blobs["d"]).hex(),
    )
    if len(bytes.fromhex(values["vin_key_hex"])) not in (16, 24, 32) \
            or len(bytes.fromhex(values["vin_iv_hex"])) != 16:
        raise ValueError("Unsupported APK key lengths")
    for name in ("hmac_access_key", "hmac_secret", "snc_secret"):
        if not re.fullmatch(r"[\x21-\x7e]{1,256}", values[name]):
            raise ValueError("Unsupported APK identity encoding")
    return values


def write_private_file(path, values):
    """Create an owner-only file; never overwrite an existing file or symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(values, output, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-apk", required=True, type=Path)
    parser.add_argument("--arm64-apk", type=Path,
                        help="ARM64 split APK, if native libraries are not in base.apk")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.exit(1, "Output already exists; choose a new private output path.\n")
    try:
        values = extract_keys(args.base_apk, args.arm64_apk)
        write_private_file(args.output, values)
    except UnsupportedBuildError as exc:
        parser.exit(1, f"{exc} No keys printed.\n")
    except Exception as exc:
        # Exceptions from DEX/crypto/native libraries can contain input values.
        parser.exit(1, f"Extraction failed ({type(exc).__name__}). No keys printed. "
                    "Check the APK version, dependencies and output path.\n")
    print("Local app-key file created. Keep it private and copy it to Home Assistant.")


if __name__ == "__main__":
    main()
