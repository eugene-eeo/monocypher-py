from monocypher.utils import ensure_bytes, ensure_range
from monocypher._monocypher import lib, ffi


def crypto_argon2i(
    password,
    salt,
    hash_size=64,
    nb_blocks=100000,
    nb_iterations=3,
    key=b'',
    ad=b'',
):
    ensure_bytes('password', password)
    ensure_bytes('salt', salt)
    ensure_range('len(salt)', len(salt), 8, float('+inf'))
    ensure_range('hash_size', hash_size, 1, float('+inf'))
    ensure_range('nb_blocks', nb_blocks, 8, float('+inf'))
    ensure_range('nb_iterations', nb_iterations, 1, float('+inf'))
    ensure_bytes('key', key)
    ensure_bytes('ad', ad)

    work_area = lib.malloc(nb_blocks * 1024)
    if work_area == ffi.NULL:
        raise RuntimeError('malloc() returned NULL')

    try:
        password_size = len(password)
        salt_size = len(salt)
        key_size = len(key)
        ad_size  = len(ad)
        hash     = ffi.new(f'uint8_t[{hash_size}]')
        password = ffi.new('uint8_t[]', password)
        salt     = ffi.new('uint8_t[]', salt)
        key      = ffi.new('uint8_t[]', key)
        ad       = ffi.new('uint8_t[]', ad)
        lib.crypto_argon2i_general(
            hash, hash_size,
            work_area, nb_blocks, nb_iterations,
            password, password_size,
            salt, salt_size,
            key, key_size,
            ad, ad_size,
        )
        lib.crypto_wipe(password, password_size)
        return bytes(hash)
    finally:
        lib.free(work_area)
