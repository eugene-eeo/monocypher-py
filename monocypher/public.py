from secrets import token_bytes
from monocypher.utils import ensure_bytes_with_length, ensure, Encodable
from monocypher.utils.crypto_public import crypto_key_exchange, crypto_key_exchange_public_key
from monocypher.utils.crypto_cmp import crypto_verify32
from monocypher.secret import SecretBox


__all__ = ('PublicKey', 'PrivateKey', 'Box')


class PublicKey(Encodable):
    KEY_SIZE = 32

    __slots__ = ('_pk',)

    def __init__(self, pk):
        ensure_bytes_with_length('pk', pk, self.KEY_SIZE)
        self._pk = pk

    def __bytes__(self):
        return self._pk

    def __eq__(self, other):
        return isinstance(other, self.__class__) and crypto_verify32(other._pk, self._pk)

    def __hash__(self):
        return hash(self._pk)


class PrivateKey(Encodable):
    KEY_SIZE = 32

    __slots__ = ('_sk',)

    def __init__(self, sk):
        ensure_bytes_with_length('sk', sk, self.KEY_SIZE)
        self._sk = sk

    @classmethod
    def generate(cls):
        return cls(token_bytes(cls.KEY_SIZE))

    @property
    def public_key(self):
        return PublicKey(crypto_key_exchange_public_key(self._sk))

    def __bytes__(self):
        return self._sk

    def __eq__(self, other):
        return isinstance(other, self.__class__) and crypto_verify32(other._sk, self._sk)

    def __hash__(self):
        return hash(self._sk)


class Box(SecretBox):
    __slots__ = ()

    def __init__(self, your_sk, their_pk):
        ensure(isinstance(your_sk, PrivateKey), TypeError, 'your_sk should be a PrivateKey instance')
        ensure(isinstance(their_pk, PublicKey), TypeError, 'their_pk should be a PublicKey instance')
        super().__init__(crypto_key_exchange(
            your_sk.encode(),
            their_pk.encode(),
        ))

    def shared_key(self):
        return self._key
