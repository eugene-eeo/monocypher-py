from monocypher.utils import ensure_bytes, ensure_range, ensure_context
from monocypher._monocypher import lib, ffi


BLAKE2B_KEY_MIN = 0
BLAKE2B_KEY_MAX = 64
BLAKE2B_HASH_MIN = 1
BLAKE2B_HASH_MAX = 64


def crypto_blake2b(
    msg,           # bytes
    key=b'',       # bytes[0..64]
    hash_size=64,  # int[1..64]
):
    ensure_bytes('key', key)
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    hash = ffi.new('uint8_t[]', hash_size)
    size = len(msg)
    msg  = ffi.from_buffer('uint8_t[]', msg)

    lib.crypto_blake2b_general(
        hash, hash_size,
        key, len(key),
        msg, size,
    )
    return bytes(hash)


def crypto_blake2b_init(
    key=b'',
    hash_size=64,
):
    ensure_bytes('key', key)
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    ctx = ffi.new('crypto_blake2b_ctx *')
    lib.crypto_blake2b_general_init(ctx, hash_size, key, len(key))
    return ctx


def crypto_blake2b_update(ctx, msg):
    ensure_context('ctx', ctx, 'crypto_blake2b_ctx *', 'crypto_blake2b_init()')

    size = len(msg)
    msg  = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_blake2b_update(ctx, msg, size)
    return ctx


def crypto_blake2b_final(ctx):
    ensure_context('ctx', ctx, 'crypto_blake2b_ctx *', 'crypto_blake2b_init()')

    hash = ffi.new('uint8_t[]', ctx.hash_size)
    lib.crypto_blake2b_final(ctx, hash)
    return bytes(hash)


# Optional (Ed25519 + SHA256)

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
    ensure_context('ctx', ctx, 'crypto_sha512_ctx *', 'crypto_sha512_init()')

    size = len(msg)
    msg  = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_sha512_update(ctx, msg, size)
    return ctx


def crypto_sha512_final(ctx):
    ensure_context('ctx', ctx, 'crypto_sha512_ctx *', 'crypto_sha512_init()')

    hash = ffi.new('uint8_t[64]')
    lib.crypto_sha512_final(ctx, hash)
    return bytes(hash)


def crypto_hmac_sha512(
    msg,  # bytes
    key,  # bytes
):
    ensure_bytes('key', key)

    hmac = ffi.new('uint8_t[64]')
    size = len(msg)
    msg  = ffi.from_buffer('uint8_t[]', msg)

    lib.crypto_hmac_sha512(hmac, key, len(key), msg, size)
    return bytes(hmac)


def crypto_hmac_sha512_init(key):
    ensure_bytes('key', key)

    ctx = ffi.new('crypto_hmac_sha512_ctx *')

    lib.crypto_hmac_sha512_init(ctx, key, len(key))
    return ctx


def crypto_hmac_sha512_update(ctx, msg):
    ensure_context('ctx', ctx, 'crypto_hmac_sha512_ctx *', 'crypto_hmac_sha512_init()')

    size = len(msg)
    msg  = ffi.from_buffer('uint8_t[]', msg)
    lib.crypto_hmac_sha512_update(ctx, msg, size)
    return ctx


def crypto_hmac_sha512_final(ctx):
    ensure_context('ctx', ctx, 'crypto_hmac_sha512_ctx *', 'crypto_hmac_sha512_init()')

    hmac = ffi.new('uint8_t[64]')
    lib.crypto_hmac_sha512_final(ctx, hmac)
    return bytes(hmac)
