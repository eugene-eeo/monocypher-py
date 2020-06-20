from monocypher.utils import ensure_length
from monocypher._monocypher import lib, ffi


def crypto_verify16(a, b):
    ensure_length('a', a, 16)
    ensure_length('b', b, 16)

    a = ffi.from_buffer('uint8_t[16]', a)
    b = ffi.from_buffer('uint8_t[16]', b)

    with a, b:
        return lib.crypto_verify16(a, b) == 0


def crypto_verify32(a, b):
    ensure_length('a', a, 32)
    ensure_length('b', b, 32)

    a = ffi.from_buffer('uint8_t[32]', a)
    b = ffi.from_buffer('uint8_t[32]', b)

    with a, b:
        return lib.crypto_verify32(a, b) == 0


def crypto_verify64(a, b):
    ensure_length('a', a, 64)
    ensure_length('b', b, 64)

    a = ffi.from_buffer('uint8_t[64]', a)
    b = ffi.from_buffer('uint8_t[64]', b)

    with a, b:
        return lib.crypto_verify64(a, b) == 0


def crypto_wipe(buf):
    with ffi.from_buffer('uint8_t[]', buf) as buf:
        lib.crypto_wipe(buf, len(buf))
