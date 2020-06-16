from monocypher.utils import ensure_bytes, ensure_bytes_with_length, Encodable, random
from monocypher.utils.crypto_cmp import crypto_verify32
from monocypher.utils.crypto_sign import (
    crypto_check, crypto_sign, crypto_sign_public_key,
    crypto_from_eddsa_private, crypto_from_eddsa_public,
)
from monocypher.public import PublicKey, PrivateKey


__all__ = ('SignatureError', 'SignedMessage', 'VerifyKey', 'SigningKey')


class SignatureError(Exception):
    pass


class SignedMessage(bytes):
    @classmethod
    def from_parts(cls, sig, msg):
        obj = cls(sig + msg)
        obj._sig = sig
        obj._msg = msg
        return obj

    @property
    def sig(self):
        return self._sig

    @property
    def msg(self):
        return self._msg


class VerifyKey(Encodable):
    KEY_SIZE = 32
    SIG_SIZE = 64

    __slots__ = ('_pk',)

    def __init__(self, pk):
        ensure_bytes_with_length('pk', pk, self.KEY_SIZE)
        self._pk = pk

    def __eq__(self, other):
        return isinstance(other, self.__class__) and crypto_verify32(other._pk, self._pk)

    def __hash__(self):
        return hash(self._pk)

    def verify(self, msg, sig=None):
        ensure_bytes('msg', msg)
        if sig is None:
            if len(msg) < self.SIG_SIZE:
                raise SignatureError('corrupted message')
            sig = msg[:self.SIG_SIZE]
            msg = msg[self.SIG_SIZE:]

        if not crypto_check(sig=sig, public_key=self._pk, msg=msg):
            raise SignatureError('invalid signature')
        return msg

    def __bytes__(self):
        return self._pk

    def to_public_key(self):
        return PublicKey(crypto_from_eddsa_public(self._pk))


class SigningKey(Encodable):
    KEY_SIZE = 32
    SIG_SIZE = 64

    __slots__ = ('_sk',)

    def __init__(self, sk):
        ensure_bytes_with_length('sk', sk, self.KEY_SIZE)
        self._sk = sk

    def __eq__(self, other):
        return isinstance(other, self.__class__) and crypto_verify32(other._sk, self._sk)

    def __hash__(self):
        return hash(self._sk)

    @classmethod
    def generate(cls):
        return cls(random(cls.KEY_SIZE))

    def sign(self, msg):
        sig = crypto_sign(secret_key=self._sk, msg=msg)
        return SignedMessage.from_parts(sig=sig, msg=msg)

    def __bytes__(self):
        return self._sk

    @property
    def verify_key(self):
        return VerifyKey(crypto_sign_public_key(self._sk))

    def to_private_key(self):
        return PrivateKey(crypto_from_eddsa_private(self._sk))
