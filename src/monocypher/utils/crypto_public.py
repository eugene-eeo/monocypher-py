from monocypher.utils import ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


def crypto_key_exchange(
    your_secret_key,   # bytes[32]
    their_public_key,  # bytes[32]
):
    ensure_bytes_with_length('your_secret_key', your_secret_key, 32)
    ensure_bytes_with_length('their_public_key', their_public_key, 32)

    shared = ffi.new('uint8_t[32]')

    lib.crypto_key_exchange(shared, your_secret_key, their_public_key)
    return bytes(shared)


def crypto_key_exchange_public_key(your_secret_key):
    ensure_bytes_with_length('your_secret_key', your_secret_key, 32)

    pk = ffi.new('uint8_t[32]')

    lib.crypto_key_exchange_public_key(pk, your_secret_key)
    return bytes(pk)


def crypto_x25519(
    your_secret_key,   # bytes[32]
    their_public_key,  # bytes[32]
):
    ensure_bytes_with_length('your_secret_key', your_secret_key, 32)
    ensure_bytes_with_length('their_public_key', their_public_key, 32)

    shared = ffi.new('uint8_t[32]')

    lib.crypto_x25519(shared, your_secret_key, their_public_key)
    return bytes(shared)


def crypto_x25519_public_key(your_secret_key):
    ensure_bytes_with_length('secret_key', your_secret_key, 32)

    pk = ffi.new('uint8_t[32]')

    lib.crypto_x25519_public_key(pk, your_secret_key)
    return bytes(pk)
