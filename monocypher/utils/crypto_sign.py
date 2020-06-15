from monocypher.utils import ensure_bytes, ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


def crypto_sign_public_key(
    secret_key,  # bytes[32],
):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    pk = ffi.new('uint8_t[32]')
    sk = ffi.new('uint8_t[32]', secret_key)
    lib.crypto_sign_public_key(pk, sk)
    lib.crypto_wipe(sk, 32)
    return bytes(pk)


def crypto_sign(
    secret_key,  # bytes[32],
    msg,         # bytes
):
    ensure_bytes('msg', msg)
    ensure_bytes_with_length('secret_key', secret_key, 32)

    msg_size = len(msg)
    sig = ffi.new('uint8_t[64]')
    pk  = ffi.new('uint8_t[32]', crypto_sign_public_key(secret_key))
    sk  = ffi.new('uint8_t[32]', secret_key)
    msg = ffi.new('uint8_t[]', msg)

    lib.crypto_sign(sig,
                    sk, pk,
                    msg, msg_size)
    lib.crypto_wipe(sk, 32)
    return bytes(sig)


def crypto_check(
    sig,         # bytes[64]
    public_key,  # bytes[32]
    msg,         # bytes
):
    ensure_bytes_with_length('sig', sig, 64)
    ensure_bytes_with_length('public_key', public_key, 32)
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    sig = ffi.new('uint8_t[64]', sig)
    pk  = ffi.new('uint8_t[32]', public_key)
    msg = ffi.new('uint8_t[]', msg)

    rv = lib.crypto_check(sig, pk, msg, msg_size)
    return rv == 0


def crypto_from_eddsa_private(
    eddsa,  # bytes[32]
):
    ensure_bytes_with_length('eddsa', eddsa, 32)

    eddsa  = ffi.new('uint8_t[32]', eddsa)
    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_eddsa_private(x25519, eddsa)
    lib.crypto_wipe(eddsa, 32)
    return bytes(x25519)


def crypto_from_eddsa_public(
    eddsa,  # bytes[32]
):
    ensure_bytes_with_length('eddsa', eddsa, 32)

    eddsa  = ffi.new('uint8_t[32]', eddsa)
    x25519 = ffi.new('uint8_t[32]')

    lib.crypto_from_eddsa_public(x25519, eddsa)
    return bytes(x25519)


# Optional interface (Ed25519)

def crypto_ed25519_public_key(
    secret_key,  # bytes[32]
):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    pk = ffi.new('uint8_t[32]')
    sk = ffi.new('uint8_t[32]', secret_key)

    lib.crypto_ed25519_public_key(pk, sk)
    lib.crypto_wipe(sk, 32)
    return bytes(pk)


def crypto_ed25519_sign(
    secret_key,  # bytes[32]
    msg,         # bytes
):
    ensure_bytes_with_length('secret_key', secret_key, 32)
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    sig = ffi.new('uint8_t[64]')
    sk  = ffi.new('uint8_t[32]', secret_key)
    pk  = ffi.new('uint8_t[32]')
    msg = ffi.new('uint8_t[]', msg)

    lib.crypto_ed25519_public_key(pk, sk)
    lib.crypto_ed25519_sign(sig, sk, pk, msg, msg_size)
    lib.crypto_wipe(sk, 32)
    return bytes(sig)


def crypto_ed25519_check(
    sig,         # bytes[64]
    public_key,  # bytes[32]
    msg,         # bytes
):
    ensure_bytes_with_length('sig', sig, 64)
    ensure_bytes_with_length('public_key', public_key, 32)
    ensure_bytes('msg', msg)

    msg_size = len(msg)
    sig = ffi.new('uint8_t[64]', sig)
    pk  = ffi.new('uint8_t[32]', public_key)
    msg = ffi.new('uint8_t[]', msg)

    rv = lib.crypto_ed25519_check(sig, pk, msg, msg_size)
    return rv == 0


def crypto_from_ed25519_private(
    ed25519,  # bytes[32]
):
    ensure_bytes_with_length('ed25519', ed25519, 32)

    ed25519 = ffi.new('uint8_t[32]', ed25519)
    x25519  = ffi.new('uint8_t[32]')

    lib.crypto_from_ed25519_private(x25519, ed25519)
    lib.crypto_wipe(ed25519, 32)
    return bytes(x25519)


def crypto_from_ed25519_public(
    ed25519,  # bytes[32]
):
    ensure_bytes_with_length('ed25519', ed25519, 32)

    ed25519 = ffi.new('uint8_t[32]', ed25519)
    x25519  = ffi.new('uint8_t[32]')

    lib.crypto_from_ed25519_public(x25519, ed25519)
    return bytes(x25519)
