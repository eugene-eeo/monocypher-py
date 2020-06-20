from monocypher.utils import ensure_range
from monocypher._monocypher import lib, ffi


BLAKE2B_KEY_MIN = 0
BLAKE2B_KEY_MAX = 64
BLAKE2B_HASH_MIN = 1
BLAKE2B_HASH_MAX = 64


def crypto_blake2b(msg, key=b'', hash_size=64):
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    hash = ffi.new('uint8_t[]', hash_size)
    msg  = ffi.from_buffer('uint8_t[]', msg)
    key  = ffi.from_buffer('uint8_t[]', key)

    lib.crypto_blake2b_general(
        hash, hash_size,
        key, len(key),
        msg, len(msg),
    )
    return bytes(hash)


def crypto_blake2b_init(key=b'', hash_size=64):
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    ctx = ffi.new('crypto_blake2b_ctx *')
    key = ffi.from_buffer('uint8_t[]', key)
    lib.crypto_blake2b_general_init(ctx, hash_size, key, len(key))
    return ctx


def crypto_blake2b_update(ctx, msg):
    msg = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_blake2b_update(ctx, msg, len(msg))


def crypto_blake2b_final(ctx):
    hash = ffi.new('uint8_t[]', ctx.hash_size)
    lib.crypto_blake2b_final(ctx, hash)
    return bytes(hash)
