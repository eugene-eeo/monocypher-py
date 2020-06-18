import pytest
import hashlib
from hypothesis import given, example
from hypothesis.strategies import integers, binary
from monocypher.utils.crypto_hash import (
    crypto_blake2b,
    crypto_blake2b_init, crypto_blake2b_update, crypto_blake2b_final,
    BLAKE2B_KEY_MIN, BLAKE2B_KEY_MAX,
    BLAKE2B_HASH_MIN, BLAKE2B_HASH_MAX,
    # optional
    crypto_sha512,
    crypto_sha512_init, crypto_sha512_update, crypto_sha512_final,
    crypto_hmac_sha512,
    crypto_hmac_sha512_init, crypto_hmac_sha512_update, crypto_hmac_sha512_final,
)

from tests.utils import get_vectors


MSG         = binary()
BLAKE2B_KEY = binary(min_size=BLAKE2B_KEY_MIN, max_size=BLAKE2B_KEY_MAX)
SHA512_KEY  = binary()
HASH_SIZE   = integers(min_value=BLAKE2B_HASH_MIN, max_value=BLAKE2B_HASH_MAX)
CHUNKS      = integers(min_value=1, max_value=200)


def chunked_update(ctx, update_func, msg, chunks):
    chunk_size = len(msg) // chunks
    for i in range(chunks):
        chunk = (
            msg if i == chunks - 1 else
            msg[:chunk_size]
        )
        update_func(ctx, chunk)
        msg = msg[chunk_size:]


@given(MSG, BLAKE2B_KEY, HASH_SIZE, CHUNKS)
def test_crypto_blake2b(msg, key, hash_size, chunks):
    digest = crypto_blake2b(msg, key, hash_size)
    ctx = crypto_blake2b_init(key, hash_size)

    chunked_update(ctx, crypto_blake2b_update, msg, chunks)
    assert crypto_blake2b_final(ctx) == digest


@given(MSG, CHUNKS)
def test_crypto_sha512(msg, chunks):
    digest = crypto_sha512(msg)
    ctx = crypto_sha512_init()

    chunked_update(ctx, crypto_sha512_update, msg, chunks)
    assert crypto_sha512_final(ctx) == digest


@given(MSG, SHA512_KEY, CHUNKS)
def test_crypto_hmac_sha512(msg, key, chunks):
    digest = crypto_hmac_sha512(msg, key)
    ctx = crypto_hmac_sha512_init(key)

    chunked_update(ctx, crypto_hmac_sha512_update, msg, chunks)
    assert crypto_hmac_sha512_final(ctx) == digest


# check that we are calling sha512 correctly!
@given(MSG)
@example(b'')
def test_crypto_sha512_against_stdlib(msg):
    assert crypto_sha512(msg) == hashlib.sha512(msg).digest()


# test vectors
def test_crypto_blake2b_vectors():
    for vec in get_vectors('blake2-kat.json'):
        if vec['hash'] == 'blake2b':
            msg = bytes(bytearray.fromhex(vec['in']))
            key = bytes(bytearray.fromhex(vec['key']))
            out = bytes(bytearray.fromhex(vec['out']))
            assert crypto_blake2b(msg, key=key) == out


def test_crypto_hmac_sha512_vectors():
    for vec in get_vectors('hmac-sha512.json'):
        msg = bytes(bytearray.fromhex(vec['data']))
        key = bytes(bytearray.fromhex(vec['key']))
        out = bytes(bytearray.fromhex(vec['hash']))
        assert crypto_hmac_sha512(msg, key=key) == out


@pytest.mark.parametrize('hash,ctx_init,ctx_update,ctx_final,init_args', [
    (crypto_blake2b,     crypto_blake2b_init,     crypto_blake2b_update,     crypto_blake2b_final,     {'key': b'', 'hash_size': 64}),
    (crypto_sha512,      crypto_sha512_init,      crypto_sha512_update,      crypto_sha512_final,      {}),
    (crypto_hmac_sha512, crypto_hmac_sha512_init, crypto_hmac_sha512_update, crypto_hmac_sha512_final, {'key': b''}),
])
@given(MSG)
def test_crypto_hash_bytes_like(hash, ctx_init, ctx_update, ctx_final, init_args, msg):
    for wrapper in [bytes, bytearray, memoryview]:
        msg_wrapped = wrapper(msg)
        digest = hash(msg=msg_wrapped, **init_args)

        ctx = ctx_init(**init_args)
        ctx_update(ctx, msg_wrapped)

        assert digest == hash(msg=msg, **init_args)
        assert digest == ctx_final(ctx)
