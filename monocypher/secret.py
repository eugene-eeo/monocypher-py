from secrets import token_bytes
from monocypher.utils import ensure_bytes_with_length, ensure_bytes, Encodable
from monocypher.utils.crypto_aead import crypto_lock, crypto_unlock, CryptoError


__all__ = ('EncryptedMessage', 'SecretBox')


class EncryptedMessage(bytes):
    @classmethod
    def from_parts(cls, nonce, mac, ciphertext):
        obj = cls(nonce + mac + ciphertext)
        obj._nonce = nonce
        obj._ciphertext = mac + ciphertext
        obj._detacted_mac = mac
        obj._detached_ciphertext = ciphertext
        return obj

    @property
    def nonce(self):
        return self._nonce

    @property
    def ciphertext(self):
        return self._ciphertext

    @property
    def detached_mac(self):
        return self._detacted_mac

    @property
    def detached_ciphertext(self):
        return self._detacted_ciphertext


class SecretBox(Encodable):
    KEY_SIZE   = 32
    NONCE_SIZE = 24
    MAC_SIZE   = 16

    __slots__ = ('key',)

    def __init__(self, key):
        ensure_bytes_with_length('key', key, self.KEY_SIZE)
        self._key = key

    def __bytes__(self):
        return self._key

    def encrypt(self, msg, nonce=None):
        mac, nonce, ct = crypto_lock(
            key=self.shared_key,
            msg=msg,
            nonce=token_bytes(24) if nonce is None else nonce,
        )
        return EncryptedMessage.from_parts(nonce=nonce,
                                           mac=mac,
                                           ciphertext=ct)

    def decrypt_raw(self, ciphertext, nonce, mac):
        return crypto_unlock(key=self.shared_key,
                             mac=mac,
                             nonce=nonce,
                             ciphertext=ciphertext)

    def decrypt(self, ciphertext, nonce=None):
        ensure_bytes('ciphertext', ciphertext)
        if nonce is None:
            # get from ciphertext, assume that it is encoded
            # with the default EncryptedMessage
            if len(ciphertext) < 24 + 16:
                raise CryptoError('malformed ciphertext')
            nonce      = ciphertext[:24]
            mac        = ciphertext[24:24 + 16]
            ciphertext = ciphertext[24 + 16:]
        else:
            ensure_bytes_with_length('nonce', nonce, self.NONCE_SIZE)
            if len(ciphertext) < 16:
                raise CryptoError('malformed ciphertext')
            mac        = ciphertext[:16]
            ciphertext = ciphertext[16:]
        return self.decrypt_raw(ciphertext, nonce, mac)
