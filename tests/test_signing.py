from pytest import raises
from hypothesis import given
from hypothesis.strategies import binary
from secrets import token_bytes
from monocypher.bindings import crypto_sign_public_key
from monocypher.signing import SignatureError, SigningKey, VerifyKey


MSG = binary()
KEY = binary(min_size=SigningKey.KEY_SIZE, max_size=SigningKey.KEY_SIZE)
SIG = binary(min_size=SigningKey.SIG_SIZE, max_size=SigningKey.SIG_SIZE)


def test_signingkey():
    key_bytes = token_bytes(SigningKey.KEY_SIZE)
    sk = SigningKey(key_bytes)

    # hashable
    hash(sk)

    assert sk.encode() == key_bytes
    assert sk == SigningKey(key_bytes)


def test_verifykey():
    sk = SigningKey.generate()
    pk = sk.verify_key

    # hashable
    hash(pk)

    assert pk.encode() == crypto_sign_public_key(sk.encode())
    assert pk == VerifyKey(pk.encode())


@given(KEY)
def test_signing_conversion(sk_key_bytes):
    sk = SigningKey(sk_key_bytes)
    pk = sk.verify_key

    sk_x25519 = sk.to_private_key()
    pk_x25519 = pk.to_public_key()

    assert sk_x25519.public_key == pk_x25519


@given(KEY, MSG)
def test_sign_verify(sk_key_bytes, msg):
    sk = SigningKey(sk_key_bytes)
    pk = sk.verify_key

    signed_message = sk.sign(msg)

    assert signed_message.msg == msg
    assert len(signed_message.sig) == SigningKey.SIG_SIZE

    assert pk.verify(signed_message) == msg
    assert pk.verify(msg, sig=signed_message.sig) == msg


@given(KEY, MSG, SIG)
def test_sign_verify_fake(sk_key_bytes, msg, fake_sig):
    sk = SigningKey(sk_key_bytes)
    pk = sk.verify_key

    signed_message = sk.sign(msg)
    if signed_message.sig != fake_sig:
        with raises(SignatureError):
            pk.verify(fake_sig + signed_message.msg)

        with raises(SignatureError):
            pk.verify(signed_message.msg, sig=fake_sig)

    with raises(SignatureError):
        # not long enough to contain signature
        pk.verify(msg[:14])
