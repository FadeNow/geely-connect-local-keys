"""Format checks for the locally supplied Android 1.3.0 (10300) build.

Fingerprints and offsets identify code layouts, not keys. All vendor bytes
come from the owner's APK; none are embedded in this module.
"""
import base64
import hashlib
import hmac
import re
import struct
import zlib


FINGERPRINTS = {
    "classes.dex": "485ea7f010cb82a172dfd05708afeadc9318d23461738d4502b2a8d3f43f9d70",
    "libenv.so": "9be70337d8ec4cc81ae14fc0fbb8f74ab15007e79ea057194d45a9a46defb888",
    "libiwallca.so": "267a71f978f1425937e7e9146139151e321f1364cd04d814fb675c07243836a4",
}


class UnsupportedBuildError(ValueError):
    """A fixed diagnostic that cannot include APK contents."""

    def __str__(self):
        return ("Unsupported APK build or layout. Supported: com.geely.global "
                "Android 1.1.1 and the validated ARM64 1.3.0 (10300) build. "
                "Other releases, repackaged builds and iOS are not supported.")


def verify_member(name, data):
    if hashlib.sha256(data).hexdigest() != FINGERPRINTS[name]:
        raise UnsupportedBuildError()


def restore_dex_header(body, map_offset):
    """Restore only the header, using the retained DEX section map."""
    if len(body) < 112 or not 112 <= map_offset <= len(body) - 4:
        raise ValueError("Invalid embedded DEX bounds")
    count = struct.unpack_from("<I", body, map_offset)[0]
    if not 8 <= count <= 40 or map_offset + 4 + 12 * count != len(body):
        raise ValueError("Invalid embedded DEX map size")
    table = {}
    for index in range(count):
        kind, reserved, size, offset = struct.unpack_from(
            "<HHII", body, map_offset + 4 + index * 12
        )
        if reserved or kind in table or not size or offset >= len(body):
            raise ValueError("Invalid embedded DEX section")
        table[kind] = (size, offset)
    if table.get(0) != (1, 0) or table.get(0x1000) != (1, map_offset):
        raise ValueError("Invalid embedded DEX map identity")
    header = [len(body), 112, 0x12345678, 0, 0, map_offset]
    for kind, item_size in ((1, 4), (2, 4), (3, 12), (4, 8), (5, 8), (6, 32)):
        size, offset = table[kind]
        if offset < 112 or offset + size * item_size > map_offset:
            raise ValueError("Invalid embedded DEX index bounds")
        header.extend((size, offset))
    data_offset = min(offset for kind, (_, offset) in table.items() if kind >= 0x1000)
    header.extend((len(body) - data_offset, data_offset))
    result = bytearray(body)
    result[:8] = b"dex\n035\x00"
    struct.pack_into("<20I", result, 32, *header)
    result[12:32] = hashlib.sha1(result[32:]).digest()
    struct.pack_into("<I", result, 8, zlib.adler32(result[12:]))
    return bytes(result)


def regional_dex(container):
    verify_member("classes.dex", container)
    # The ninth embedded DEX contains vj/i. Only its header is transformed;
    # the original section map and method data remain in the owner's APK.
    start, size = 34915572, 7041708
    return restore_dex_header(container[start:start + size], size - 220)


def find_signing_key(memory, message, signature):
    """Identify a candidate only by matching the app's own HMAC result.

    `memory` must be the isolated emulator's stack, never host process memory.
    No known key, key prefix or fixed stack offset is used.
    """
    expected = base64.b64decode(signature, validate=True)
    if len(expected) != 32:
        raise ValueError("Unexpected native signature format")
    # Adjacent stack buffers can form one printable run. Test each bounded
    # suffix ending at a NUL, rather than assuming a nonprintable prefix.
    candidates = set()
    for match in re.finditer(rb"[\x21-\x7e]{16,}\x00", memory):
        tail = match[0][-257:-1]
        candidates.update(tail[-length:] for length in range(16, len(tail) + 1))
    matches = [key for key in candidates if hmac.compare_digest(
        hmac.new(key, message, hashlib.sha256).digest(), expected
    )]
    if len(matches) != 1:
        raise ValueError("Could not uniquely authenticate the local signing key")
    return matches[0]
