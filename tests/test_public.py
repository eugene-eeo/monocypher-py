from hypothesis import given
from hypothesis.strategies import binary
from pytest import raises
from monocypher.utils import random
from monocypher.public import PublicKey, PrivateKey, Box, SealedBox
from monocypher.secret import CryptoError


def test_private_key():
    e = random(PrivateKey.KEY_SIZE)
    sk = PrivateKey(e)

    # hashable
    hash(sk)

    assert sk.encode() == e
    assert sk == PrivateKey(e)


def test_public_key():
    sk = PrivateKey.generate()
    pk = sk.public_key

    # hashable
    hash(pk)

    assert pk == PublicKey(pk.encode())


MSG = binary()


@given(MSG)
def test_public_workflow(msg):
    sk_a = PrivateKey.generate()
    sk_b = PrivateKey.generate()

    # not allowed to give 2 PrivateKeys
    with raises(TypeError):
        Box(sk_a, sk_b)

    box_a = Box(sk_a, sk_b.public_key)
    box_b = Box(sk_b, sk_a.public_key)
    assert box_a.shared_key == box_b.shared_key

    ct = box_a.encrypt(msg)
    assert box_b.decrypt(ct) == msg


@given(MSG)
def test_sealed_box(msg):
    sk = PrivateKey.generate()
    fake_sk = PrivateKey.generate()

    if fake_sk == sk:
        return

    box = SealedBox(sk.public_key)
    enc = box.encrypt(msg)

    # cannot decrypt what we have just sent!
    with raises(RuntimeError):
        box.decrypt(enc)

    assert SealedBox(sk).decrypt(enc) == msg

    with raises(CryptoError):
        SealedBox(fake_sk).decrypt(enc)


def test_sealed_box_raises_error():
    with raises(TypeError):
        SealedBox(b'blah')
