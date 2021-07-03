from monocypher.utils import ensure_bytes_with_length, Key, random
from monocypher.bindings.crypto_aead import crypto_lock, crypto_unlock


__all__ = ('EncryptedMessage', 'SecretBox', 'CryptoError')


class CryptoError(Exception):
    pass


class EncryptedMessage(bytes):
    """
    A bytes subclass representing an encrypted message.
    By default, monocypher-python represents encrypted and authenticated
    messages as ``nonce + mac + ciphertext``, i.e.:

        >>> msg = sbox.encrypt(b'...')
        >>> msg == msg.nonce + msg.detached_mac + msg.detached_ciphertext
        True

    """

    @classmethod
    def from_parts(cls, nonce, mac, ciphertext):
        obj = cls(nonce + mac + ciphertext)
        obj._nonce = nonce
        obj._ciphertext = mac + ciphertext
        return obj

    @property
    def nonce(self):
        """
        Returns the nonce.

        :rtype: :class:`bytes`
        """
        return self._nonce

    @property
    def ciphertext(self):
        """
        Returns the concatenated mac and ciphertext.
        This is equivalent to concatenating :py:obj:`.detached_mac`
        and :py:obj:`.detached_ciphertext`.
        This can be passed to :py:meth:`SecretBox.decrypt`
        separately from :py:attr:`.nonce`:

            >>> msg = sbox.encrypt(b'...')
            >>> sbox.decrypt(msg.ciphertext, msg.nonce)
            b'...'

        :rtype: :class:`bytes`
        """
        return self._ciphertext

    @property
    def detached_mac(self):
        """
        Returns the detached mac.

        :rtype: :class:`bytes`
        """
        return self.ciphertext[:SecretBox.MAC_SIZE]

    @property
    def detached_ciphertext(self):
        """
        Returns the detached ciphertext.
        This is different from :py:obj:`.ciphertext`,
        since the former returns the mac and the encryption.
        Just sending this (e.g. to save space) is not recommended
        since you will not be sure if the encryption has been
        tampered with.

        :rtype: :class:`bytes`
        """
        return self.ciphertext[SecretBox.MAC_SIZE:]


class SecretBox(Key):
    """
    Encrypts messages using XChacha20, and authenticates them using Poly1305.
    The `key` parameter can be produced in different ways,
    e.g. via key exchange (e.g. :py:class:`~monocypher.public.Box`),
    or password key derivation (:py:func:`~monocypher.pwhash.argon2i`).

    :param key: A :py:class:`bytes` object of length :py:obj:`.KEY_SIZE`.
    """

    KEY_SIZE   = 32  #: Length of a valid key in bytes.
    NONCE_SIZE = 24  #: Length of a valid nonce in bytes.
    MAC_SIZE   = 16  #: Length of a valid MAC in bytes.

    __slots__ = ('_key',)

    def __init__(self, key):
        ensure_bytes_with_length('key', key, self.KEY_SIZE)
        self._key = key

    def __bytes__(self):
        return self._key

    def encrypt(self, msg, nonce=None):
        """
        Encrypt the given message `msg`, optionally with a specified `nonce`.
        If the given `nonce` is ``None``, then it is automatically generated.
        See :class:`.EncryptedMessage` for details on how the encrypted message
        is encoded.

        :param msg: Message to encrypt (a bytes-like object).
        :param nonce: Optional :py:obj:`bytes` object of length :py:obj:`.NONCE_SIZE`.

        :rtype: :class:`.EncryptedMessage`
        """
        if nonce is None:
            nonce = random(self.NONCE_SIZE)
        mac, ct = crypto_lock(key=self._key, msg=msg, nonce=nonce)
        return EncryptedMessage.from_parts(nonce=nonce,
                                           mac=mac,
                                           ciphertext=ct)

    def decrypt_raw(self, ciphertext, nonce, mac):
        """
        Decrypt the given `ciphertext`, `nonce`, and `mac`.
        If the decryption is successful, the plaintext message
        is returned. Otherwise a :py:class:`.CryptoError` is raised.

        :param ciphertext: Detached ciphertext to decrypt (bytes).
        :param nonce: The nonce, a :py:obj:`bytes` object of length :py:obj:`.NONCE_SIZE`.
        :param mac: The MAC, a :py:obj:`bytes` object of length :py:obj:`.MAC_SIZE`.

        :rtype: :class:`bytes`
        """
        msg = crypto_unlock(key=self._key,
                            mac=mac,
                            nonce=nonce,
                            ciphertext=ciphertext)
        if msg is None:
            raise CryptoError('failed to decrypt ciphertext')
        return msg

    def decrypt(self, ciphertext, nonce=None):
        """
        Wrapper around :py:meth:`.decrypt_raw` that decrypts the given
        `ciphertext`, using the given `nonce` if supplied; otherwise it
        is extracted from the `ciphertext`.
        The MAC should be part of the `ciphertext` (see the encryption format
        in :py:class:`.EncryptedMessage`).

        :param ciphertext: A bytes-like object or :py:class:`.EncryptedMessage`.
        :param nonce: Optional nonce if it isn't included in the ciphertext.

        :rtype: :class:`bytes`
        """
        if nonce is None:
            # get from ciphertext, assume that it is encoded
            # with the default EncryptedMessage
            if len(ciphertext) < self.NONCE_SIZE + self.MAC_SIZE:
                raise CryptoError('malformed ciphertext')
            nonce      = ciphertext[:self.NONCE_SIZE]
            mac        = ciphertext[self.NONCE_SIZE:self.NONCE_SIZE + self.MAC_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE + self.MAC_SIZE:]
        else:
            if len(ciphertext) < self.MAC_SIZE:
                raise CryptoError('malformed ciphertext')
            mac        = ciphertext[:self.MAC_SIZE]
            ciphertext = ciphertext[self.MAC_SIZE:]
        return self.decrypt_raw(ciphertext, nonce, mac)
