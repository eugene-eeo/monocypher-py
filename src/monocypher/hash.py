from monocypher._monocypher import ffi
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


# Direct Interface
blake2b     = crypto_blake2b
sha512      = crypto_sha512
hmac_sha512 = crypto_hmac_sha512


class Context:
    __slots__ = ('_ctx',)

    def __init__(self, ctx):
        self._ctx = ctx

    def _copy_ctx(self):
        ctx_new  = ffi.new(self._ctx_type)
        ctx_void = ffi.cast('uint8_t *', self._ctx)
        dst_void = ffi.cast('uint8_t *', ctx_new)
        ffi.memmove(
            dst_void,
            ctx_void,
            ffi.sizeof(ctx_new[0]),
        )
        return ctx_new

    def copy(self):
        """
        Returns a copy of the hash object.
        This can be useful for, e.g. computing digests of content
        with a common prefix.
        """
        cls = self.__class__
        obj = cls.__new__(cls)
        obj._ctx = self._copy_ctx()
        return obj

    def update(self, data):
        """
        Update the context with a `bytes-like object
        <https://docs.python.org/3/glossary.html#term-bytes-like-object>`_.
        """
        self._update(self._ctx, data)

    def digest(self):
        """
        Returns the digest of the data passed to :py:meth:`.update` so far.

        :rtype: :py:class:`bytes`
        """
        # crypto_blake2b_final wipes the context on call
        return self._final(self._copy_ctx())


class Blake2bContext(Context):
    __slots__ = ()

    KEY_MIN  = BLAKE2B_KEY_MIN
    KEY_MAX  = BLAKE2B_KEY_MAX
    HASH_MIN = BLAKE2B_HASH_MIN
    HASH_MAX = BLAKE2B_HASH_MAX

    def __init__(self, key=b'', hash_size=64):
        super().__init__(crypto_blake2b_init(key, hash_size))

    _ctx_type = 'crypto_blake2b_ctx *'
    _update = staticmethod(crypto_blake2b_update)
    _final  = staticmethod(crypto_blake2b_final)


class SHA512Context(Context):
    __slots__ = ()

    def __init__(self):
        super().__init__(crypto_sha512_init())

    _ctx_type = 'crypto_sha512_ctx *'
    _update = staticmethod(crypto_sha512_update)
    _final  = staticmethod(crypto_sha512_final)


class HMACSHA512Context(Context):
    __slots__ = ()

    def __init__(self, key):
        super().__init__(crypto_hmac_sha512_init(key))

    _ctx_type = 'crypto_hmac_sha512_ctx *'
    _update = staticmethod(crypto_hmac_sha512_update)
    _final  = staticmethod(crypto_hmac_sha512_final)
