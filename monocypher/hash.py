from monocypher.utils.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
    # sha512
    crypto_sha512,
    crypto_sha512_init, crypto_sha512_update, crypto_sha512_final,
    crypto_hmac_sha512,
    crypto_hmac_sha512_init, crypto_hmac_sha512_update, crypto_hmac_sha512_final,
)


__all__ = ('Blake2bContext', 'blake2b',
           'SHA512Context', 'sha512',
           'HMACSHA512Context', 'hmac_sha512')


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


class SHA512Context:
    __slots__ = ('_ctx', '_digest')

    def __init__(self):
        self._ctx = crypto_sha512_init()
        self._digest = None

    def update(self, data):
        if self._digest is not None:
            raise RuntimeError('already finalised')
        crypto_sha512_update(self._ctx, data)

    def digest(self):
        if self._digest is None:
            self._digest = crypto_sha512_final(self._ctx)
        return self._digest


class HMACSHA512Context:
    __slots__ = ('_ctx', '_digest')

    def __init__(self, key):
        self._ctx = crypto_hmac_sha512_init(key)
        self._digest = None

    def update(self, data):
        if self._digest is not None:
            raise RuntimeError('already finalised')
        crypto_hmac_sha512_update(self._ctx, data)

    def digest(self):
        if self._digest is None:
            self._digest = crypto_hmac_sha512_final(self._ctx)
        return self._digest


blake2b     = crypto_blake2b
sha512      = crypto_sha512
hmac_sha512 = crypto_hmac_sha512
