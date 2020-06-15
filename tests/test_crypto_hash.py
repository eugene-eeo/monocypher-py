from hypothesis import given
from hypothesis.strategies import integers, binary
from monocypher.utils.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
)


MSG       = binary()
KEY       = binary(min_size=BLAKE2B_KEY_MIN, max_size=BLAKE2B_KEY_MAX)
HASH_SIZE = integers(min_value=BLAKE2B_HASH_MIN, max_value=BLAKE2B_HASH_MAX)
CHUNKS    = integers(min_value=1, max_value=200)


@given(MSG, KEY, HASH_SIZE, CHUNKS)
def test_crypto_blake2b(msg, key, hash_size, chunks):
    digest = crypto_blake2b(msg, key, hash_size)
    ctx = crypto_blake2b_init(key, hash_size)

    chunk_size = len(msg) // chunks

    for i in range(chunks):
        chunk = (
            msg if i == chunks - 1 else
            msg[:chunk_size]
        )
        crypto_blake2b_update(ctx, chunk)
        msg = msg[chunk_size:]

    assert crypto_blake2b_final(ctx) == digest
