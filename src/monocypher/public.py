from monocypher.utils import ensure_bytes_with_length, ensure, Key, random
from monocypher.bindings.crypto_public import crypto_key_exchange, crypto_key_exchange_public_key
from monocypher.secret import SecretBox


__all__ = ('PublicKey', 'PrivateKey', 'Box')


class PublicKey(Key):
    """
    X25519 public key. This can be published.

    :param pk: The public key (:py:class:`bytes`).
    """

    KEY_SIZE = 32  #: Length of a public key in bytes.

    __slots__ = ('_pk',)

    def __init__(self, pk):
        ensure_bytes_with_length('pk', pk, self.KEY_SIZE)
        self._pk = pk

    def __bytes__(self):
        return self._pk


class PrivateKey(Key):
    """
    X25519 private key. This **must** be kept secret.

    :param sk: The private key (:py:class:`bytes`).
    """

    KEY_SIZE = 32  #: Length of a private key in bytes.

    __slots__ = ('_sk',)

    def __init__(self, sk):
        ensure_bytes_with_length('sk', sk, self.KEY_SIZE)
        self._sk = sk

    @classmethod
    def generate(cls):
        """
        Generates a random :class:`.PrivateKey` object.

        :rtype: :class:`.PrivateKey`
        """
        return cls(random(cls.KEY_SIZE))

    @property
    def public_key(self):
        """
        Returns the corresponding :class:`.PublicKey` object.

        :rtype: :class:`.PublicKey`
        """
        return PublicKey(crypto_key_exchange_public_key(self._sk))

    def __bytes__(self):
        return self._sk


class Box(SecretBox):
    """
    A subclass of :class:`~monocypher.secret.SecretBox` object with the
    encryption key being the shared key computed from the key exchange.
    The shared key is computed using X25519 and HChaCha20.
    For details see `Monocypher's documentation <https://monocypher.org/manual/key_exchange>`_.

    :param your_sk: Your private key (a :class:`.PrivateKey` object).
    :param their_pk: Their public key (a :class:`.PublicKey` object).
    """

    __slots__ = ()

    def __init__(self, your_sk, their_pk):
        ensure(isinstance(your_sk, PrivateKey), TypeError, 'your_sk should be a PrivateKey instance')
        ensure(isinstance(their_pk, PublicKey), TypeError, 'their_pk should be a PublicKey instance')
        super().__init__(crypto_key_exchange(
            your_sk.encode(),
            their_pk.encode(),
        ))

    @property
    def shared_key(self):
        """
        Returns the shared secret. This value is safe for use as the key
        for other symmetric ciphers.
        """
        return self._key


class SealedBox:
    """
    SealedBox enables you to send messages decryptable only by the receipient.
    Each time a message is encrypted, a new ephemeral keypair is generated;
    the ephemeral private key is used in key-exchange with the `receipient_key`
    and thrown away after encryption.

    :param receipient_key: A :py:class:`.PublicKey` or :py:class:`.PrivateKey`
                           object. If a :py:class:`.PrivateKey` is provided,
                           then the SealedBox is able to decrypt messages.
                           Otherwise, SealedBox can only encrypt messages.
    """

    __slots__ = ('_pk', '_sk')

    def __init__(self, receipient_key):
        if isinstance(receipient_key, PrivateKey):
            self._pk = receipient_key.public_key
            self._sk = receipient_key
        elif isinstance(receipient_key, PublicKey):
            self._pk = receipient_key
            self._sk = None
        else:
            raise TypeError('receipient_key should be a PublicKey or PrivateKey instance')

    def encrypt(self, msg):
        """
        Encrypt the given `msg`. This works using a similar construction
        as that from libsodium's `crypto_box_seal <https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes>`_,
        but using Monocypher's high level functions.

        :param msg: The message to encrypt (bytes).
        :rtype: :py:class:`bytes`
        """
        ephemeral_sk = PrivateKey.generate()
        ephemeral_pk = ephemeral_sk.public_key

        nonce = bytes(Box.NONCE_SIZE)
        ct = Box(ephemeral_sk, self._pk).encrypt(msg, nonce=nonce).ciphertext
        return ephemeral_pk.encode() + ct

    def decrypt(self, ciphertext):
        """
        Decrypt the given `ciphertext`. Returns the original message if
        decryption was successful, otherwise raises :py:class:`~monocypher.secret.CryptoError`.
        If the provided key was a :py:class:`.PublicKey`, raises a
        :py:class:`RuntimeError`.

        :param ciphertext: The ciphertext to decrypt (bytes-like object).
        :rtype: :py:class:`bytes`
        """
        ensure(self._sk is not None, RuntimeError, 'SecretBox cannot decrypt using a PublicKey')
        e_pk = ciphertext[:PublicKey.KEY_SIZE]  # Ephemeral PublicKey
        ct   = ciphertext[PublicKey.KEY_SIZE:]  # MAC + encrypted message
        box  = Box(self._sk, PublicKey(e_pk))
        return box.decrypt(
            ciphertext=ct,
            nonce=bytes(Box.NONCE_SIZE),
        )
