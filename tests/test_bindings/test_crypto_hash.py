from hypothesis import given
from hypothesis.strategies import integers, binary
from monocypher.bindings.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
)

from tests.utils import get_vectors, chunked


MSG         = binary()
BLAKE2B_KEY = binary(min_size=BLAKE2B_KEY_MIN, max_size=BLAKE2B_KEY_MAX)
HASH_SIZE   = integers(min_value=BLAKE2B_HASH_MIN, max_value=BLAKE2B_HASH_MAX)
CHUNK_SIZE  = integers(min_value=1, max_value=200)


@given(MSG, BLAKE2B_KEY, HASH_SIZE, CHUNK_SIZE)
def test_crypto_blake2b(msg, key, hash_size, chunk_size):
    digest = crypto_blake2b(msg, key, hash_size)
    ctx = crypto_blake2b_init(key, hash_size)

    for chunk in chunked(msg, chunk_size):
        crypto_blake2b_update(ctx, chunk)
    assert crypto_blake2b_final(ctx) == digest


# test vectors
def test_crypto_blake2b_vectors():
    for vec in get_vectors('blake2-kat.json'):
        if vec['hash'] == 'blake2b':
            msg = bytearray.fromhex(vec['in'])
            key = bytearray.fromhex(vec['key'])
            out = bytearray.fromhex(vec['out'])
            assert crypto_blake2b(msg, key=key) == out


# Check that we can use bytes-like objects
@given(MSG)
def test_crypto_hash_bytes_like(msg):
    args = {'key': b'', 'hash_size': 64}

    for wrapper in [bytes, bytearray, memoryview]:
        msg_wrapped = wrapper(msg)
        digest = crypto_blake2b(msg=msg_wrapped, **args)

        ctx = crypto_blake2b_init(**args)
        crypto_blake2b_update(ctx, msg_wrapped)

        assert digest == crypto_blake2b(msg=msg, **args)
        assert digest == crypto_blake2b_final(ctx)
