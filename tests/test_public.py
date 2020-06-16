from pytest import raises
from secrets import token_bytes
from monocypher.public import PublicKey, PrivateKey, Box


def test_private_key():
    e = token_bytes(PrivateKey.KEY_SIZE)
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


def test_public_workflow():
    sk_a = PrivateKey.generate()
    sk_b = PrivateKey.generate()

    # not allowed to give 2 PrivateKeys
    with raises(TypeError):
        Box(sk_a, sk_b)

    box_a = Box(sk_a, sk_b.public_key)
    box_b = Box(sk_b, sk_a.public_key)
    assert box_a.shared_key() == box_b.shared_key()

    msg = box_a.encrypt(b'abc')
    assert box_b.decrypt(msg) == b'abc'
