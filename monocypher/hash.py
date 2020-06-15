from monocypher.utils.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
)


__all__ = ('Blake2bContext', 'blake2b')


class Blake2bContext:
    __slots__ = ('_ctx', '_digest')

    KEY_MIN  = BLAKE2B_KEY_MIN
    KEY_MAX  = BLAKE2B_KEY_MAX
    HASH_MIN = BLAKE2B_HASH_MIN
    HASH_MAX = BLAKE2B_HASH_MAX

    def __init__(self, key=b'', hash_size=64):
        self._ctx = crypto_blake2b_init(key, hash_size)
        self._digest = None

    def update(self, data):
        if self._digest is not None:
            raise RuntimeError('already finalised')
        crypto_blake2b_update(self._ctx, data)

    def digest(self):
        if self._digest is None:
            self._digest = crypto_blake2b_final(self._ctx)
        return self._digest


def blake2b(msg, key=b'', hash_size=64):
    return crypto_blake2b(msg, key=key, hash_size=hash_size)
