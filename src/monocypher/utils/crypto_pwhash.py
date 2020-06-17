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
    ensure_range('len(salt)', len(salt), min=8)
    ensure_range('hash_size', hash_size, min=1)
    ensure_range('nb_blocks', nb_blocks, min=8)
    ensure_range('nb_iterations', nb_iterations, min=1)
    ensure_bytes('key', key)
    ensure_bytes('ad', ad)

    work_area = lib.malloc(nb_blocks * 1024)
    if work_area == ffi.NULL:  # pragma: no cover
        raise RuntimeError('malloc() returned NULL')

    try:
        hash = ffi.new('uint8_t[]', hash_size)
        lib.crypto_argon2i_general(
            hash, hash_size,
            work_area, nb_blocks, nb_iterations,
            password, len(password),
            salt, len(salt),
            key, len(key),
            ad, len(ad),
        )
        return bytes(hash)
    finally:
        lib.free(work_area)
