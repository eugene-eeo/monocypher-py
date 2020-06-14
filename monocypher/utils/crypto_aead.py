from monocypher.utils import ensure, ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


class CryptoError(Exception):
    pass


def crypto_lock(
    key,      # bytes[32]
    nonce,    # bytes[24]
    message,  # bytes
):
    ensure(isinstance(message, bytes), TypeError, 'message must be bytes')
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('nonce', nonce, 24)

    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]', bytes(16))
    pt    = ffi.new('uint8_t[]', message)
    ct    = ffi.new('uint8_t[]', bytes(len(message)))

    lib.crypto_lock(
        mac,
        ct,
        key,
        nonce,
        pt,
        len(message),
    )
    # ct is zero padded at the end
    return bytes(mac), bytes(nonce), bytes(ct)[:-1]


def crypto_unlock(
    key,         # bytes[32]
    mac,         # bytes[16]
    nonce,       # bytes[24]
    ciphertext,  # bytes
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('mac', mac, 16)
    ensure(isinstance(ciphertext, bytes), TypeError, 'ciphertext must be bytes')
    ensure_bytes_with_length('nonce', nonce, 24)

    pt    = ffi.new('uint8_t[]', bytes(len(ciphertext)))
    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]', mac)
    ct    = ffi.new('uint8_t[]', ciphertext)

    rt = lib.crypto_unlock(
        pt,
        key,
        nonce,
        mac,
        ct,
        len(ciphertext),
    )
    ensure(rt == 0, CryptoError, 'failed to unlock')
    return bytes(pt)[:-1]


def crypto_lock_aead(
    key,
    nonce,
    message,
    additional_data,
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure(isinstance(message, bytes), TypeError, 'message must be bytes')
    ensure(isinstance(additional_data, bytes), TypeError, 'additional_data must be bytes')

    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]', bytes(16))
    pt    = ffi.new('uint8_t[]', message)
    ad    = ffi.new('uint8_t[]', additional_data)
    ct    = ffi.new('uint8_t[]', bytes(len(message)))

    lib.crypto_lock_aead(
        mac,
        ct,
        key,
        nonce,
        ad, len(additional_data),
        pt, len(message),
    )
    # ct is zero padded at the end
    return bytes(mac), bytes(nonce), bytes(ct)[:-1]


def crypto_unlock_aead(
    key,
    mac,
    nonce,
    ciphertext,
    additional_data,
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('mac', mac, 16)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure(isinstance(ciphertext, bytes), TypeError, 'message must be bytes')
    ensure(isinstance(additional_data, bytes), TypeError, 'additional_data must be bytes')

    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]', mac)
    pt    = ffi.new('uint8_t[]', bytes(len(ciphertext)))
    ad    = ffi.new('uint8_t[]', additional_data)
    ct    = ffi.new('uint8_t[]', ciphertext)

    rt = lib.crypto_unlock_aead(
        pt,
        key,
        nonce,
        mac,
        ad, len(additional_data),
        ct, len(ciphertext),
    )
    ensure(rt == 0, CryptoError, 'failed to unlock')
    # ct is zero padded at the end
    return bytes(pt)[:-1]
