from monocypher.utils import copy_context
from monocypher.bindings.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
)


__all__ = ('Blake2bContext', 'blake2b')


# Direct Interface
blake2b = crypto_blake2b


class Blake2bContext:
    """
    Can be used to incrementally compute the `blake2b` hash of a
    long stream of bytes (e.g. a large file) without having to read
    all of it into memory.
    Parameters have the same meaning as :py:func:`.blake2b`.
    This class is compatible with :py:mod:`hashlib`'s hash objects;
    see :py:mod:`hashlib` for details.
    """

    KEY_MIN  = BLAKE2B_KEY_MIN    #: Minimum Blake2b key length
    KEY_MAX  = BLAKE2B_KEY_MAX    #: Maximum Blake2b key length
    HASH_MIN = BLAKE2B_HASH_MIN   #: Minimum Blake2b digest length
    HASH_MAX = BLAKE2B_HASH_MAX   #: Maximum Blake2b digest length

    name = 'blake2b'
    block_size = 128

    __slots__ = ('_ctx', '_hash_size')

    def __init__(self, data=b'', key=b'', hash_size=64):
        self._ctx = crypto_blake2b_init(key=key, hash_size=hash_size)
        self._hash_size = hash_size
        self.update(data)

    @property
    def digest_size(self):
        return self._hash_size

    def _copy_ctx(self):
        return copy_context(self._ctx, 'crypto_blake2b_ctx *')

    def copy(self):
        obj = self.__class__.__new__(self.__class__)
        obj._ctx = self._copy_ctx()
        obj._hash_size = self._hash_size
        return obj

    def update(self, data):
        crypto_blake2b_update(self._ctx, data)

    def digest(self):
        # crypto_blake2b_final wipes the context on call
        return crypto_blake2b_final(self._copy_ctx())

    def hexdigest(self):
        return self.digest().hex()
