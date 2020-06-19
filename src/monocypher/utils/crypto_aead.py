from monocypher._monocypher import lib, ffi


def crypto_lock(key, nonce, msg, ad=b''):
    """
    :returns: (bytes(mac), bytes(ciphertext))
    """
    key   = ffi.from_buffer('uint8_t[32]', key)
    nonce = ffi.from_buffer('uint8_t[24]', nonce)
    mac   = ffi.new('uint8_t[16]')
    ct    = ffi.new('uint8_t[]', len(msg))
    msg   = ffi.from_buffer('uint8_t[]', msg)
    ad    = ffi.from_buffer('uint8_t[]', ad)

    lib.crypto_lock_aead(
        mac,
        ct,
        key,
        nonce,
        ad, len(ad),
        msg, len(msg),
    )
    return bytes(mac), bytes(ct)


def crypto_unlock(key, mac, nonce, ciphertext, ad=b''):
    """
    :returns: None or bytes(msg)
    """
    key   = ffi.from_buffer('uint8_t[32]', key)
    mac   = ffi.from_buffer('uint8_t[16]', mac)
    nonce = ffi.from_buffer('uint8_t[24]', nonce)
    ct = ffi.from_buffer('uint8_t[]', ciphertext)
    ad = ffi.from_buffer('uint8_t[]', ad)
    pt = ffi.new('uint8_t[]', len(ciphertext))
    rv = lib.crypto_unlock_aead(
        pt,
        key,
        nonce,
        mac,
        ad, len(ad),
        ct, len(ct),
    )
    if rv != 0:
        return None
    return bytes(pt)
