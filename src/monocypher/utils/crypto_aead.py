from monocypher.utils import ensure_bytes, ensure_bytes_with_length
from monocypher._monocypher import lib, ffi


def crypto_lock(
    key,
    nonce,
    msg,
    ad=b'',
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure_bytes('msg', msg)
    ensure_bytes('ad', ad)

    mac = ffi.new('uint8_t[16]')
    ct  = ffi.new('uint8_t[]', len(msg))

    lib.crypto_lock_aead(
        mac,
        ct,
        key,
        nonce,
        ad, len(ad),
        msg, len(msg),
    )
    # ct is zero padded at the end
    return bytes(mac), bytes(ct)


def crypto_unlock(
    key,
    mac,
    nonce,
    ciphertext,
    ad=b'',
):
    ensure_bytes_with_length('key', key, 32)
    ensure_bytes_with_length('mac', mac, 16)
    ensure_bytes_with_length('nonce', nonce, 24)
    ensure_bytes('ciphertext', ciphertext)
    ensure_bytes('ad', ad)

    pt = ffi.new('uint8_t[]', len(ciphertext))
    rv = lib.crypto_unlock_aead(
        pt,
        key,
        nonce,
        mac,
        ad, len(ad),
        ciphertext, len(ciphertext),
    )
    if rv != 0:
        return None
    # pt is zero padded at the end
    return bytes(pt)
