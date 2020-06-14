from monocypher.utils import ensure_bytes, ensure_range, ensure
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
    ctx = ffi.new('crypto_blake2b_ctx*')
    key = ffi.new('uint8_t[]', key)
    lib.crypto_blake2b_general_init(ctx, hash_size, key, key_size)
    return ctx


def crypto_blake2b_update(
    ctx,
    msg,
):
    ensure(ffi.typeof(ctx).cname == 'crypto_blake2b_ctx *', TypeError, 'ctx should be from crypto_blake2b_init()')
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    msg = ffi.new('uint8_t[]', msg)
    lib.crypto_blake2b_update(ctx, msg, msg_size)
    lib.crypto_wipe(msg, msg_size)
    return ctx


def crypto_blake2b_final(
    ctx,
):
    ensure(ffi.typeof(ctx).cname == 'crypto_blake2b_ctx *', TypeError, 'ctx should be from crypto_blake2b_init()')

    hash = ffi.new(f'uint8_t[{ctx.hash_size}]')
    lib.crypto_blake2b_final(ctx, hash)
    return bytes(hash)
