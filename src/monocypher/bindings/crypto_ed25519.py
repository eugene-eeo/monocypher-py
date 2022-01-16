from monocypher.utils import ensure_length
from monocypher._monocypher import lib, ffi


def crypto_ed25519_public_key(secret_key):
    ensure_length('secret_key', secret_key, 32)

    sk = ffi.from_buffer('uint8_t[32]', secret_key)
    pk = ffi.new('uint8_t[32]')

    lib.crypto_ed25519_public_key(pk, sk)
    return bytes(pk)


def crypto_ed25519_sign(secret_key, msg):
    ensure_length('secret_key', secret_key, 32)

    sk  = ffi.from_buffer('uint8_t[32]', secret_key)
    msg = ffi.from_buffer('uint8_t[]', msg)
    sig = ffi.new('uint8_t[64]')
    pk  = ffi.new('uint8_t[32]')

    lib.crypto_ed25519_public_key(pk, secret_key)
    lib.crypto_ed25519_sign(sig, sk, pk, msg, len(msg))
    lib.crypto_wipe(pk, 32)
    return bytes(sig)


def crypto_ed25519_check(sig, public_key, msg):
    ensure_length('sig', sig, 64)
    ensure_length('public_key', public_key, 32)

    sig = ffi.from_buffer('uint8_t[64]', sig)
    pk  = ffi.from_buffer('uint8_t[32]', public_key)
    msg = ffi.from_buffer('uint8_t[]', msg)

    rv = lib.crypto_ed25519_check(sig, pk, msg, len(msg))
    return rv == 0


def crypto_from_ed25519_private(eddsa):
    ensure_length('eddsa', eddsa, 32)

    eddsa  = ffi.from_buffer('uint8_t[32]', eddsa)
    x25519 = ffi.new('uint8_t[32]')
    lib.crypto_from_ed25519_private(x25519, eddsa)
    return bytes(x25519)


def crypto_from_ed25519_public(eddsa):
    ensure_length('eddsa', eddsa, 32)

    eddsa  = ffi.from_buffer('uint8_t[32]', eddsa)
    x25519 = ffi.new('uint8_t[32]')
    lib.crypto_from_eddsa_public(x25519, eddsa)
    return bytes(x25519)
