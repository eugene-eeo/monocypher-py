from hypothesis import given
from hypothesis.strategies import binary
from monocypher.utils.crypto_public import crypto_x25519_public_key
from monocypher.utils.crypto_sign import (
    crypto_sign, crypto_sign_public_key, crypto_check,
    crypto_from_eddsa_private, crypto_from_eddsa_public,
    # ed25519
    crypto_ed25519_public_key,
    crypto_ed25519_sign,
    crypto_ed25519_check,
    crypto_from_ed25519_private,
    crypto_from_ed25519_public,
)


SK  = binary(min_size=32, max_size=32)
SIG = binary(min_size=64, max_size=64)
MSG = binary()


@given(SK, MSG, SIG)
def test_crypto_sign_workflow(sk, message, fake_sig):
    pk = crypto_sign_public_key(sk)
    sig = crypto_sign(sk, message)
    assert crypto_check(sig, pk, message)
    if fake_sig != sig:
        assert not crypto_check(fake_sig, pk, message)


@given(SK, MSG, SK)
def test_crypto_sign_sk(sk, message, fake_sk):
    sig = crypto_sign(sk, message)
    if sk != fake_sk:
        fake_pk = crypto_sign_public_key(fake_sk)
        assert not crypto_check(sig, fake_pk, message)


@given(SK)
def test_crypto_convert(sk):
    x25519_sk = crypto_from_eddsa_private(sk)
    x25519_pk = crypto_x25519_public_key(x25519_sk)
    pk = crypto_sign_public_key(sk)
    assert crypto_from_eddsa_public(pk) == x25519_pk


@given(SK, MSG, SIG)
def test_crypto_ed25519_workflow(sk, message, fake_sig):
    pk = crypto_ed25519_public_key(sk)
    sig = crypto_ed25519_sign(sk, message)
    assert crypto_ed25519_check(sig, pk, message)
    if fake_sig != sig:
        assert not crypto_ed25519_check(fake_sig, pk, message)


@given(SK, MSG, SK)
def test_crypto_ed25519_sk(sk, message, fake_sk):
    sig = crypto_ed25519_sign(sk, message)
    if sk != fake_sk:
        fake_pk = crypto_ed25519_public_key(fake_sk)
        assert not crypto_ed25519_check(sig, fake_pk, message)


@given(SK)
def test_crypto_ed25519_convert(sk):
    x25519_sk = crypto_from_ed25519_private(sk)
    x25519_pk = crypto_x25519_public_key(x25519_sk)
    pk = crypto_ed25519_public_key(sk)
    assert crypto_from_ed25519_public(pk) == x25519_pk
