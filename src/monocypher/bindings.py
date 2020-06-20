from ._monocypher import lib, ffi
from .utils.crypto_aead import crypto_lock, crypto_unlock
from .utils.crypto_cmp import crypto_verify16, crypto_verify32, crypto_verify64
from .utils.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
)
from .utils.crypto_public import (
    crypto_key_exchange, crypto_key_exchange_public_key,
    crypto_x25519, crypto_x25519_public_key,
)
from .utils.crypto_pwhash import crypto_argon2i
from .utils.crypto_sign import (
    crypto_sign_public_key, crypto_sign, crypto_check,
    crypto_from_eddsa_private, crypto_from_eddsa_public,
)

__all__ = (
    'crypto_lock', 'crypto_unlock',
    'crypto_verify16', 'crypto_verify32', 'crypto_verify64',
    'crypto_blake2b',
    'crypto_blake2b_init', 'crypto_blake2b_update', 'crypto_blake2b_final',
    'BLAKE2B_HASH_MIN', 'BLAKE2B_HASH_MAX',
    'BLAKE2B_KEY_MIN', 'BLAKE2B_KEY_MAX',
    'crypto_key_exchange', 'crypto_key_exchange_public_key',
    'crypto_x25519', 'crypto_x25519_public_key',
    'crypto_argon2i',
    'crypto_sign_public_key', 'crypto_sign', 'crypto_check',
    'crypto_from_eddsa_private', 'crypto_from_eddsa_public',
    'crypto_wipe',
)


def crypto_wipe(buf):
    with ffi.from_buffer('uint8_t[]', buf) as buf:
        lib.crypto_wipe(buf, len(buf))
