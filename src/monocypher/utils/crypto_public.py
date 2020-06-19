from monocypher.utils import ensure_length
from monocypher._monocypher import lib, ffi


def crypto_key_exchange(your_secret_key, their_public_key):
    ensure_length('your_secret_key', your_secret_key, 32)
    ensure_length('their_public_key', their_public_key, 32)

    sk = ffi.from_buffer('uint8_t[32]', your_secret_key)
    pk = ffi.from_buffer('uint8_t[32]', their_public_key)
    shared = ffi.new('uint8_t[32]')

    lib.crypto_key_exchange(shared, sk, pk)
    return bytes(shared)


def crypto_key_exchange_public_key(your_secret_key):
    ensure_length('your_secret_key', your_secret_key, 32)

    sk = ffi.from_buffer('uint8_t[32]', your_secret_key)
    pk = ffi.new('uint8_t[32]')

    lib.crypto_key_exchange_public_key(pk, sk)
    return bytes(pk)


def crypto_x25519(your_secret_key, their_public_key):
    ensure_length('your_secret_key', your_secret_key, 32)
    ensure_length('their_public_key', their_public_key, 32)

    sk = ffi.from_buffer('uint8_t[32]', your_secret_key)
    pk = ffi.from_buffer('uint8_t[32]', their_public_key)
    shared = ffi.new('uint8_t[32]')

    lib.crypto_x25519(shared, sk, pk)
    return bytes(shared)


def crypto_x25519_public_key(your_secret_key):
    ensure_length('your_secret_key', your_secret_key, 32)

    sk = ffi.from_buffer('uint8_t[32]', your_secret_key)
    pk = ffi.new('uint8_t[32]')

    lib.crypto_x25519_public_key(pk, sk)
    return bytes(pk)
