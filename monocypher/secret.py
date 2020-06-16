from secrets import token_bytes
from monocypher.utils import ensure_bytes_with_length, ensure_bytes, Encodable
from monocypher.utils.crypto_aead import crypto_lock, crypto_unlock


__all__ = ('EncryptedMessage', 'SecretBox', 'CryptoError')


class CryptoError(Exception):
    pass


class EncryptedMessage(bytes):
    @classmethod
    def from_parts(cls, nonce, mac, ciphertext):
        obj = cls(nonce + mac + ciphertext)
        obj._nonce = nonce
        obj._ciphertext = mac + ciphertext
        return obj

    @property
    def nonce(self):
        return self._nonce

    @property
    def ciphertext(self):
        return self._ciphertext

    @property
    def detached_mac(self):
        return self.ciphertext[:SecretBox.MAC_SIZE]

    @property
    def detached_ciphertext(self):
        return self.ciphertext[SecretBox.MAC_SIZE:]


class SecretBox(Encodable):
    KEY_SIZE   = 32
    NONCE_SIZE = 24
    MAC_SIZE   = 16

    __slots__ = ('_key',)

    def __init__(self, key):
        ensure_bytes_with_length('key', key, self.KEY_SIZE)
        self._key = key

    def __bytes__(self):
        return self._key

    def encrypt(self, msg, nonce=None):
        if nonce is None:
            nonce = token_bytes(self.NONCE_SIZE)
        mac, nonce, ct = crypto_lock(key=self._key,
                                     msg=msg,
                                     nonce=nonce)
        return EncryptedMessage.from_parts(nonce=nonce,
                                           mac=mac,
                                           ciphertext=ct)

    def decrypt_raw(self, ciphertext, nonce, mac):
        msg = crypto_unlock(key=self._key,
                            mac=mac,
                            nonce=nonce,
                            ciphertext=ciphertext)
        if msg is None:
            raise CryptoError('failed to decrypt ciphertext')
        return msg

    def decrypt(self, ciphertext, nonce=None):
        ensure_bytes('ciphertext', ciphertext)
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
