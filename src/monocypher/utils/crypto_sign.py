from monocypher.utils import ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


def crypto_sign_public_key(secret_key):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    pk = ffi.new('uint8_t[32]')
    lib.crypto_sign_public_key(pk, secret_key)
    return bytes(pk)


def crypto_sign(secret_key, msg):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    msg = ffi.from_buffer('uint8_t[]', msg)
    sig = ffi.new('uint8_t[64]')
    pk  = ffi.new('uint8_t[32]')

    lib.crypto_sign_public_key(pk, secret_key)
    lib.crypto_sign(sig,
                    secret_key, pk,
                    msg, len(msg))
    return bytes(sig)


def crypto_check(sig, public_key, msg):
    ensure_bytes_with_length('sig', sig, 64)
    ensure_bytes_with_length('public_key', public_key, 32)

    msg = ffi.from_buffer('uint8_t[]', msg)
    rv = lib.crypto_check(sig, public_key, msg, len(msg))
    return rv == 0


def crypto_from_eddsa_private(eddsa):
    ensure_bytes_with_length('eddsa', eddsa, 32)

    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_eddsa_private(x25519, eddsa)
    return bytes(x25519)


def crypto_from_eddsa_public(eddsa):
    ensure_bytes_with_length('eddsa', eddsa, 32)

    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_eddsa_public(x25519, eddsa)
    return bytes(x25519)


# Optional interface (Ed25519)

def crypto_ed25519_public_key(secret_key):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    pk = ffi.new('uint8_t[32]')

    lib.crypto_ed25519_public_key(pk, secret_key)
    return bytes(pk)


def crypto_ed25519_sign(secret_key, msg):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    msg = ffi.from_buffer('uint8_t[]', msg)
    sig = ffi.new('uint8_t[64]')
    pk  = ffi.new('uint8_t[32]')

    lib.crypto_ed25519_public_key(pk, secret_key)
    lib.crypto_ed25519_sign(sig, secret_key, pk, msg, len(msg))
    return bytes(sig)


def crypto_ed25519_check(sig, public_key, msg):
    ensure_bytes_with_length('sig', sig, 64)
    ensure_bytes_with_length('public_key', public_key, 32)

    msg = ffi.from_buffer('uint8_t[]', msg)
    rv = lib.crypto_ed25519_check(sig, public_key, msg, len(msg))
    return rv == 0


def crypto_from_ed25519_private(ed25519):
    ensure_bytes_with_length('ed25519', ed25519, 32)

    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_ed25519_private(x25519, ed25519)
    return bytes(x25519)


def crypto_from_ed25519_public(ed25519):
    ensure_bytes_with_length('ed25519', ed25519, 32)

    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_ed25519_public(x25519, ed25519)
    return bytes(x25519)
