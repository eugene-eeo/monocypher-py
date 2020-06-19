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


# Optional (Ed25519 + SHA-512)

def crypto_sha512(msg):
    hash = ffi.new('uint8_t[64]')
    msg  = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_sha512(hash, msg, len(msg))
    return bytes(hash)


def crypto_sha512_init():
    ctx = ffi.new('crypto_sha512_ctx *')
    lib.crypto_sha512_init(ctx)
    return ctx


def crypto_sha512_update(ctx, msg):
    msg = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_sha512_update(ctx, msg, len(msg))


def crypto_sha512_final(ctx):
    hash = ffi.new('uint8_t[64]')
    lib.crypto_sha512_final(ctx, hash)
    return bytes(hash)


def crypto_hmac_sha512(msg, key):
    hmac = ffi.new('uint8_t[64]')
    msg  = ffi.from_buffer('uint8_t[]', msg)
    key  = ffi.from_buffer('uint8_t[]', key)

    lib.crypto_hmac_sha512(hmac, key, len(key), msg, len(msg))
    return bytes(hmac)


def crypto_hmac_sha512_init(key):
    ctx = ffi.new('crypto_hmac_sha512_ctx *')
    key = ffi.from_buffer('uint8_t[]', key)

    lib.crypto_hmac_sha512_init(ctx, key, len(key))
    return ctx


def crypto_hmac_sha512_update(ctx, msg):
    msg = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_hmac_sha512_update(ctx, msg, len(msg))


def crypto_hmac_sha512_final(ctx):
    hmac = ffi.new('uint8_t[64]')
    lib.crypto_hmac_sha512_final(ctx, hmac)
    return bytes(hmac)
