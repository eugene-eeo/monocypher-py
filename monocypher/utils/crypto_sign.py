from monocypher.utils import ensure, ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


def crypto_sign_public_key(
    secret_key,  # bytes[32],
):
    ensure_bytes_with_length('secret_key', secret_key, 32)

    pk = ffi.new('uint8_t[32]')
    sk = ffi.new('uint8_t[32]', secret_key)
    lib.crypto_sign_public_key(pk, sk)
    return bytes(pk)


def crypto_sign(
    secret_key,  # bytes[32],
    message,     # bytes
):
    ensure(isinstance(message, bytes), TypeError, 'message must be bytes')
    ensure_bytes_with_length('secret_key', secret_key, 32)

    sig = ffi.new('uint8_t[64]')
    pk  = ffi.new('uint8_t[32]', crypto_sign_public_key(secret_key))
    sk  = ffi.new('uint8_t[32]', secret_key)
    msg = ffi.new('uint8_t[]', message)

    lib.crypto_sign(sig,
                    sk, pk,
                    msg, len(message))
    return bytes(sig)


def crypto_check(
    sig,         # bytes[64]
    public_key,  # bytes[32]
    message,     # bytes
):
    ensure_bytes_with_length('sig', sig, 64)
    ensure_bytes_with_length('public_key', public_key, 32)
    ensure(isinstance(message, bytes), TypeError, 'message must be bytes')

    sig = ffi.new('uint8_t[64]', sig)
    pk  = ffi.new('uint8_t[32]', public_key)
    msg = ffi.new('uint8_t[]', message)

    rv = lib.crypto_check(sig, pk, msg, len(message))
    return rv == 0
