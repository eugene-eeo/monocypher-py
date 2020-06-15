from hypothesis import given
from hypothesis.strategies import binary
from monocypher.utils.crypto_public import (
    crypto_key_exchange, crypto_key_exchange_public_key,
    crypto_x25519, crypto_x25519_public_key,
)

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
