from monocypher.utils import ensure_bytes, ensure_range, ensure, ensure_context
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
    ensure_bytes('msg', msg)
    ensure_bytes('key', key)
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    key_size = len(key)
    msg_size = len(msg)

    hash = ffi.new(f'uint8_t[{hash_size}]')
    key  = ffi.new('uint8_t[]', key)
    msg  = ffi.new('uint8_t[]', msg)

    lib.crypto_blake2b_general(
        hash, hash_size,
        key, key_size,
        msg, msg_size
    )
    lib.crypto_wipe(key, key_size)
    lib.crypto_wipe(msg, msg_size)
    return bytes(hash)


def crypto_blake2b_init(
    key=b'',
    hash_size=64,
):
    ensure_bytes('key', key)
    ensure_range('len(key)', len(key), BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX)
    ensure_range('hash_size', hash_size, BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX)

    key_size = len(key)
    ctx = ffi.new('crypto_blake2b_ctx *')
    key = ffi.new('uint8_t[]', key)
    lib.crypto_blake2b_general_init(ctx, hash_size, key, key_size)
    return ctx


def crypto_blake2b_update(ctx, msg):
    ensure_context('ctx', ctx, 'crypto_blake2b_ctx *', 'crypto_blake2b_init()')
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    msg = ffi.new('uint8_t[]', msg)
    lib.crypto_blake2b_update(ctx, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
    return ctx


def crypto_blake2b_final(ctx):
    ensure_context('ctx', ctx, 'crypto_blake2b_ctx *', 'crypto_blake2b_init()')

    hash = ffi.new(f'uint8_t[{ctx.hash_size}]')
    lib.crypto_blake2b_final(ctx, hash)
    return bytes(hash)


# Optional (Ed25519 + SHA256)

def crypto_sha512(msg):
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    hash = ffi.new('uint8_t[64]')
    msg  = ffi.new('uint8_t[]', msg)

    lib.crypto_sha512(hash, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
    return bytes(hash)


def crypto_sha512_init():
    ctx = ffi.new('crypto_sha512_ctx *')
    lib.crypto_sha512_init(ctx)
    return ctx


def crypto_sha512_update(ctx, msg):
    ensure_context('ctx', ctx, 'crypto_sha512_ctx *', 'crypto_sha512_init()')
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    msg = ffi.new('uint8_t[]', msg)
    lib.crypto_sha512_update(ctx, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
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
    ensure_bytes('msg', msg)
    ensure_bytes('key', key)

    key_size = len(key)
    msg_size = len(msg)
    hmac = ffi.new('uint8_t[64]')
    key  = ffi.new('uint8_t[]', key)
    msg  = ffi.new('uint8_t[]', msg)

    lib.crypto_hmac_sha512(hmac, key, key_size, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
    lib.crypto_wipe(key, key_size)
    return bytes(hmac)


def crypto_hmac_sha512_init(key):
    ensure_bytes('key', key)

    key_size = len(key)
    ctx = ffi.new('crypto_hmac_sha512_ctx *')
    key = ffi.new('uint8_t[]', key)

    lib.crypto_hmac_sha512_init(ctx, key, key_size)
    return ctx


def crypto_hmac_sha512_update(ctx, msg):
    ensure_context('ctx', ctx, 'crypto_hmac_sha512_ctx *', 'crypto_hmac_sha512_init()')
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    msg = ffi.new('uint8_t[]', msg)
    lib.crypto_hmac_sha512_update(ctx, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
    return ctx


def crypto_hmac_sha512_final(ctx):
    ensure_context('ctx', ctx, 'crypto_hmac_sha512_ctx *', 'crypto_hmac_sha512_init()')

    hmac = ffi.new('uint8_t[64]')
    lib.crypto_hmac_sha512_final(ctx, hmac)
    return bytes(hmac)
