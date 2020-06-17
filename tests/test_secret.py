from hypothesis import given
from hypothesis.strategies import binary
from pytest import raises
from monocypher.utils import random
from monocypher.secret import SecretBox, CryptoError, EncryptedMessage


MSG   = binary()
KEY   = binary(min_size=SecretBox.KEY_SIZE, max_size=SecretBox.KEY_SIZE)
NONCE = binary(min_size=SecretBox.NONCE_SIZE, max_size=SecretBox.NONCE_SIZE)


@given(KEY)
def test_secret_box(key):
    box = SecretBox(key)

    assert box.encode() == key

    m = box.encrypt(b'abc', nonce=bytes(24))

    assert len(m) == len(b'abc') + box.NONCE_SIZE + box.MAC_SIZE
    assert m.nonce == bytes(24)
    assert len(m.ciphertext) == box.MAC_SIZE + len(b'abc')
    assert len(m.detached_mac) == box.MAC_SIZE
    assert len(m.detached_ciphertext) == len(b'abc')

    e = EncryptedMessage.from_parts(nonce=m.nonce,
                                    mac=m.detached_mac,
                                    ciphertext=m.detached_ciphertext[:1])

    # tamper with length
    with raises(CryptoError):
        box.decrypt(e)


@given(KEY, MSG, NONCE)
def test_secret_box_encrypt_decrypt(key, msg, nonce):
    box = SecretBox(key)
    enc = box.encrypt(msg, nonce=nonce)
    assert box.decrypt(enc) == msg
    # detached
    assert box.decrypt(enc.ciphertext, nonce=nonce) == msg


def test_secret_box_generates_nonces():
    box = SecretBox(bytes(32))
    nonce_1 = box.encrypt(b"abc").nonce
    nonce_2 = box.encrypt(b"abc").nonce
    assert nonce_1 != nonce_2


def test_secret_box_decrypt_invalid():
    key = random(SecretBox.KEY_SIZE)
    box = SecretBox(key)
    m = box.encrypt(b'abcdef')

    # no nonce!
    with raises(CryptoError):
        box.decrypt(m.ciphertext)

    # no mac!
    with raises(CryptoError):
        box.decrypt(m.detached_ciphertext, nonce=m.nonce)
