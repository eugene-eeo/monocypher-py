from monocypher.utils import ensure, ensure_bytes, ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


class CryptoError(Exception):
    pass


def crypto_lock(
    key,
    nonce,
    msg,
    additional_data=b'',
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure_bytes('msg', msg)
    ensure_bytes('additional_data', additional_data)

    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]', bytes(16))
    pt    = ffi.new('uint8_t[]', msg)
    ad    = ffi.new('uint8_t[]', additional_data)
    ct    = ffi.new('uint8_t[]', bytes(len(msg)))

    lib.crypto_lock_aead(
        mac,
        ct,
        key,
        nonce,
        ad, len(additional_data),
        pt, len(msg),
    )
    lib.crypto_wipe(pt, len(msg))
    lib.crypto_wipe(key, 32)
    # ct is zero padded at the end
    return bytes(mac), bytes(nonce), bytes(ct)[:-1]


def crypto_unlock(
    key,
    mac,
    nonce,
    ciphertext,
    additional_data=b'',
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('mac', mac, 16)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure_bytes('ciphertext', ciphertext)
    ensure_bytes('additional_data', additional_data)

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
    lib.crypto_wipe(key, 32)
    # pt is zero padded at the end
    return bytes(pt)[:-1]
