"""Offline extractor regressions using synthetic data only (no APKs or keys)."""
import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
from unittest.mock import patch
from xml.etree.ElementTree import Element
import zlib

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import extract_eu_keys as extractor
from _apk130 import (
    UnsupportedBuildError, find_signing_key, regional_dex, restore_dex_header, verify_member,
)


def _reject(function, exception=ValueError):
    try:
        function()
    except exception:
        return
    raise AssertionError("Expected rejection")


def _manifest(version, code="10300", package="com.geely.global"):
    prefix = "{http://schemas.android.com/apk/res/android}"
    return Element("manifest", {
        "package": package, prefix + "versionName": version, prefix + "versionCode": code,
    })


def test_supported_versions_and_unknown_builds():
    assert extractor._select_build(_manifest("1.1.1", "10115")) == "1.1.1"
    assert extractor._select_build(_manifest("1.3.0")) == "1.3.0"
    for manifest in (None, _manifest("1.2.0"), _manifest("1.4.0"),
                     _manifest("1.3.0", "10301"),
                     _manifest("1.3.0", package="private-input-must-not-be-printed")):
        _reject(lambda: extractor._select_build(manifest), UnsupportedBuildError)


def test_unrecognized_binary_layout_fails_closed():
    for name in ("classes.dex", "libenv.so", "libiwallca.so"):
        _reject(lambda: verify_member(name, b"synthetic-other-build"), UnsupportedBuildError)
    _reject(lambda: regional_dex(b"synthetic-container"), UnsupportedBuildError)


def _synthetic_dex():
    entries = [(0, 1, 0), (1, 1, 112), (2, 1, 116), (3, 1, 120),
               (4, 1, 132), (5, 1, 140), (6, 1, 148), (0x2002, 1, 180),
               (0x1000, 1, 192)]
    body = bytearray(192 + 4 + len(entries) * 12)
    body[:112] = b"\xa5" * 112
    body[180:184] = b"\x02ab\x00"
    struct.pack_into("<I", body, 192, len(entries))
    for index, (kind, count, offset) in enumerate(entries):
        struct.pack_into("<HHII", body, 196 + index * 12, kind, 0, count, offset)
    return body


def test_dex_header_restored_from_map_without_changing_body():
    original = _synthetic_dex()
    result = restore_dex_header(original, 192)
    assert result[:8] == b"dex\n035\x00"
    assert result[112:] == original[112:]
    assert struct.unpack_from("<III", result, 32) == (len(original), 112, 0x12345678)
    assert struct.unpack_from("<II", result, 104) == (len(original) - 180, 180)
    assert result[12:32] == hashlib.sha1(result[32:]).digest()
    assert struct.unpack_from("<I", result, 8)[0] == zlib.adler32(result[12:])


def test_dex_rejects_truncated_duplicate_and_out_of_bounds_sections():
    original = _synthetic_dex()
    _reject(lambda: restore_dex_header(original[:-1], 192))
    _reject(lambda: restore_dex_header(original, len(original)))
    duplicate = original.copy()
    struct.pack_into("<H", duplicate, 196 + 2 * 12, 1)
    _reject(lambda: restore_dex_header(duplicate, 192))
    invalid = original.copy()
    struct.pack_into("<I", invalid, 196 + 6 * 12 + 8, len(invalid) - 1)
    _reject(lambda: restore_dex_header(invalid, 192))


def test_signing_candidate_is_authenticated_with_adjacent_stack_data():
    key = b"synthetic-owner-key-for-tests-only"
    message = b"test-message"
    signature = base64.b64encode(hmac.new(key, message, hashlib.sha256).digest())
    # Reproduce adjacent printable buffers: the key has no nonprintable prefix.
    memory = b"\x00unrelated-printable-stack-data" + key + b"\x00" + b"x" * 80 + b"\x00"
    assert find_signing_key(memory, message, signature) == key
    assert find_signing_key(memory + key + b"\x00", message, signature) == key
    _reject(lambda: find_signing_key(memory, b"wrong-message", signature))
    _reject(lambda: find_signing_key(b"no-matching-key\x00", message, signature))
    _reject(lambda: find_signing_key(memory, message, base64.b64encode(b"short")))


def test_private_output_never_overwrites_files_or_symlinks():
    values = {"synthetic": "not-a-vendor-key"}
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "keys.json"
        extractor.write_private_file(output, values)
        assert json.loads(output.read_text()) == values
        if os.name == "posix":
            assert stat.S_IMODE(output.stat().st_mode) == 0o600
        _reject(lambda: extractor.write_private_file(output, {}), FileExistsError)
        assert json.loads(output.read_text()) == values
        link = Path(directory) / "link.json"
        link.symlink_to(output)
        _reject(lambda: extractor.write_private_file(link, {}), FileExistsError)
        assert json.loads(output.read_text()) == values


def _run_cli(output, error=None, values=None):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(sys, "argv", ["extract_eu_keys.py", "--base-apk", "fake.apk", "--output", str(output)]), \
            patch.object(extractor, "extract_keys", side_effect=error, return_value=values), \
            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = 0
        try:
            extractor.main()
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue() + stderr.getvalue()


def test_cli_errors_do_not_print_input_values_or_create_output():
    secret = "SYNTHETIC_PRIVATE_INPUT"
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "keys.json"
        for error in (ValueError(secret), UnsupportedBuildError(secret)):
            code, text = _run_cli(output, error=error)
            assert code == 1 and secret not in text and "No keys printed" in text
            assert not output.exists()
        code, text = _run_cli(output, error=UnsupportedBuildError())
        assert "1.1.1" in text and "1.3.0 (10300)" in text


def test_cli_success_does_not_print_keys():
    values = {"synthetic": "SYNTHETIC_PRIVATE_OUTPUT"}
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "keys.json"
        code, text = _run_cli(output, values=values)
        assert code == 0 and values["synthetic"] not in text
        assert json.loads(output.read_text()) == values
