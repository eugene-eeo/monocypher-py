from monocypher.utils import ensure_bytes_with_length, Key, random
from monocypher.bindings.crypto_sign import (
    crypto_check, crypto_sign, crypto_sign_public_key,
    crypto_from_eddsa_private, crypto_from_eddsa_public,
)
from monocypher.public import PublicKey, PrivateKey


__all__ = ('SignatureError', 'SignedMessage', 'VerifyKey', 'SigningKey')


class SignatureError(Exception):
    pass


class SignedMessage(bytes):
    """
    A subclass of :py:class:`bytes` representing a signed message.
    By default, the signature will be prepended to the message.
    """

    @classmethod
    def from_parts(cls, sig, msg):
        obj = cls(sig + msg)
        obj._sig = sig
        obj._msg = msg
        return obj

    @property
    def sig(self):
        """
        Returns the signature part.

        :rtype: :py:class:`bytes`
        """
        return self._sig

    @property
    def msg(self):
        """
        Returns the message part.

        :rtype: :py:class:`bytes`
        """
        return self._msg


class VerifyKey(Key):
    """
    EdDSA public key. This can be published.

    :param pk: The public key (:py:class:`bytes`),
               should be :py:obj:`.KEY_SIZE` bytes long.
    """

    KEY_SIZE = 32  #: Length of a public key.
    SIG_SIZE = 64  #: Length of a signature.

    __slots__ = ('_pk',)

    def __init__(self, pk):
        ensure_bytes_with_length('pk', pk, self.KEY_SIZE)
        self._pk = pk

    def verify(self, signed, sig=None):
        """
        Verify the given `signed` message. If `sig` is `None`, then the signature
        is assumed to be prepended to `signed`. Return the original message if the
        verification succeeds, otherwise :py:class:`.SignatureError` is raised.

        :param signed: A bytes-like object, or a :py:class:`.SignedMessage` object.
        :param sig: None, or a :py:class:`bytes` object with length :py:obj:`.SIG_SIZE`.
        """
        msg = signed
        if sig is None:
            if len(signed) < self.SIG_SIZE:
                raise SignatureError('corrupted message')
            sig = signed[:self.SIG_SIZE]
            msg = signed[self.SIG_SIZE:]

        if not crypto_check(sig=sig, public_key=self._pk, msg=msg):
            raise SignatureError('invalid signature')
        return msg

    def __bytes__(self):
        return self._pk

    def to_public_key(self):
        """
        Converts from a :py:class:`.VerifyKey` to a
        :py:class:`~monocypher.public.PublicKey` object.
        See notes about using the same key for both signing
        and key-exchange in :py:obj:`.SigningKey.to_private_key`.

        :rtype: :py:class:`~monocypher.public.PublicKey`
        """
        return PublicKey(crypto_from_eddsa_public(self._pk))


class SigningKey(Key):
    """
    EdDSA private key. This should be kept secret.

    :param sk: The secret key (:py:class:`bytes`),
               should be :py:obj:`.KEY_SIZE` bytes long.
    """

    KEY_SIZE = 32  #: Length of a secret key.
    SIG_SIZE = 64  #: Length of a signature.

    __slots__ = ('_sk',)

    def __init__(self, sk):
        ensure_bytes_with_length('sk', sk, self.KEY_SIZE)
        self._sk = sk

    @classmethod
    def generate(cls):
        """
        Generates a random :py:class:`.SigningKey` object.

        :rtype: :py:class:`.SigningKey`
        """
        return cls(random(cls.KEY_SIZE))

    def sign(self, msg):
        """
        Signs the given `msg`.

        :rtype: :py:class:`.SignedMessage`
        """
        sig = crypto_sign(secret_key=self._sk, msg=msg)
        return SignedMessage.from_parts(sig=sig, msg=msg)

    def __bytes__(self):
        return self._sk

    @property
    def verify_key(self):
        """
        Return the corresponding :py:class:`.VerifyKey` object.

        :rtype: :py:class:`.VerifyKey`
        """
        return VerifyKey(crypto_sign_public_key(self._sk))

    def to_private_key(self):
        """
        Converts from a :py:class:`.SigningKey` to a
        :py:class:`~monocypher.public.PrivateKey` object.
        The conversion is one-way and deterministic.
        Note that although the conversion is sound, you
        should not (without good reason) use the same private
        key for signing and key-exchange.

        :rtype: :py:class:`~monocypher.public.PrivateKey`
        """
        return PrivateKey(crypto_from_eddsa_private(self._sk))
