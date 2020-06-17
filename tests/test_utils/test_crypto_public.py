from hypothesis import given
from hypothesis.strategies import binary
from monocypher.utils.crypto_public import (
    crypto_key_exchange, crypto_key_exchange_public_key,
    crypto_x25519, crypto_x25519_public_key,
)
from tests.utils import hex2bytes

SK = binary(min_size=32, max_size=32)


@given(SK, SK, SK)
def test_crypto_key_exchange_workflow(a_sk, b_sk, random_seq):
    a_pk = crypto_key_exchange_public_key(a_sk)
    b_pk = crypto_key_exchange_public_key(b_sk)
    a_shared = crypto_key_exchange(a_sk, b_pk)
    b_shared = crypto_key_exchange(b_sk, a_pk)
    assert a_shared == b_shared

    if random_seq != b_pk:
        assert crypto_key_exchange(a_sk, random_seq) != a_shared
        assert crypto_key_exchange(b_sk, random_seq) != b_shared


@given(SK, SK, SK)
def test_crypto_x25519_workflow(a_sk, b_sk, random_seq):
    a_pk = crypto_x25519_public_key(a_sk)
    b_pk = crypto_x25519_public_key(b_sk)
    a_shared = crypto_x25519(a_sk, b_pk)
    b_shared = crypto_x25519(b_sk, a_pk)
    assert a_shared == b_shared

    if random_seq != b_pk:
        assert crypto_x25519(a_sk, random_seq) != a_shared
        assert crypto_x25519(b_sk, random_seq) != b_shared


def test_crypto_x25519():
    sk_a = hex2bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    sk_b = hex2bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    pk_a = crypto_x25519_public_key(sk_a)
    pk_b = crypto_x25519_public_key(sk_b)

    assert pk_a == hex2bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert pk_b == hex2bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert crypto_x25519(sk_a, pk_b) == hex2bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert crypto_x25519(sk_b, pk_a) == hex2bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
