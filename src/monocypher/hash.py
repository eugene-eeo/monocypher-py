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


class Context:
    __slots__ = ('_ctx', '_digest')

    def __init__(self, ctx):
        self._ctx = ctx
        self._digest = None

    def update(self, data):
        """
        Update the context with the `bytes-like object
        <https://docs.python.org/3/glossary.html#term-bytes-like-object>`_.
        If the :py:meth:`.digest` method was already called,
        then this method raises :py:class:`RuntimeError`.

        :raises: :py:class:`RuntimeError`
        """
        if self._digest is not None:
            raise RuntimeError('already finalised')
        self._update(self._ctx, data)

    def digest(self):
        """
        Returns the hash.

        :rtype: :py:class:`bytes`
        """
        if self._digest is None:
            self._digest = self._final(self._ctx)
        return self._digest


class Blake2bContext(Context):
    __slots__ = ()

    KEY_MIN  = BLAKE2B_KEY_MIN
    KEY_MAX  = BLAKE2B_KEY_MAX
    HASH_MIN = BLAKE2B_HASH_MIN
    HASH_MAX = BLAKE2B_HASH_MAX

    def __init__(self, key=b'', hash_size=64):
        super().__init__(crypto_blake2b_init(key, hash_size))

    _update = staticmethod(crypto_blake2b_update)
    _final  = staticmethod(crypto_blake2b_final)


class SHA512Context(Context):
    __slots__ = ()

    def __init__(self):
        super().__init__(crypto_sha512_init())

    _update = staticmethod(crypto_sha512_update)
    _final  = staticmethod(crypto_sha512_final)


class HMACSHA512Context(Context):
    __slots__ = ()

    def __init__(self, key):
        super().__init__(crypto_hmac_sha512_init(key))

    _update = staticmethod(crypto_hmac_sha512_update)
    _final  = staticmethod(crypto_hmac_sha512_final)


blake2b     = crypto_blake2b
sha512      = crypto_sha512
hmac_sha512 = crypto_hmac_sha512
