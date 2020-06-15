from secrets import token_bytes
from monocypher.utils import ensure_bytes_with_length, ensure
from monocypher.utils.crypto_public import crypto_key_exchange, crypto_key_exchange_public_key
from monocypher.secret import SecretBox


__all__ = ('PublicKey', 'PrivateKey', 'Box')


class PublicKey:
    __slots__ = ('_pk',)

    KEY_SIZE = 32

    def __init__(self, pk):
        ensure_bytes_with_length('pk', pk, self.KEY_SIZE)
        self._pk = pk

    def encode(self):
        return self._pk

    def __eq__(self, other):
        return type(other) is self.__class__ and other._pk == self._pk

    def __hash__(self, other):
        return hash(self._pk)


class PrivateKey:
    __slots__ = ('_sk',)

    KEY_SIZE = 32

    def __init__(self, sk):
        ensure_bytes_with_length('sk', sk, self.KEY_SIZE)
        self._sk = sk

    @classmethod
    def generate(cls):
        return cls(token_bytes(cls.KEY_SIZE))

    @property
    def public_key(self):
        return PublicKey(crypto_key_exchange_public_key(self._sk))

    def encode(self):
        return self._sk

    def __eq__(self, other):
        return type(other) is self.__class__ and other._sk == self._sk

    def __hash__(self, other):
        return hash(self._sk)


class Box(SecretBox):
    def __init__(self, your_sk: PrivateKey, their_pk: PublicKey):
        ensure(isinstance(your_sk, PrivateKey), 'your_sk should be a PrivateKey instance')
        ensure(isinstance(their_pk, PublicKey), 'their_pk should be a PublicKey instance')
        super().__init__(crypto_key_exchange(
            your_sk.encode(),
            their_pk.encode(),
        ))

    def shared_key(self):
        return self._key
