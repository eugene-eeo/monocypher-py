import pytest
import hashlib
import hmac
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

from tests.utils import get_vectors, chunked


MSG         = binary()
BLAKE2B_KEY = binary(min_size=BLAKE2B_KEY_MIN, max_size=BLAKE2B_KEY_MAX)
SHA512_KEY  = binary()
HASH_SIZE   = integers(min_value=BLAKE2B_HASH_MIN, max_value=BLAKE2B_HASH_MAX)
CHUNK_SIZE  = integers(min_value=1, max_value=200)


@given(MSG, BLAKE2B_KEY, HASH_SIZE, CHUNK_SIZE)
def test_crypto_blake2b(msg, key, hash_size, chunk_size):
    digest = crypto_blake2b(msg, key, hash_size)
    ctx = crypto_blake2b_init(key, hash_size)

    for chunk in chunked(msg, chunk_size):
        crypto_blake2b_update(ctx, chunk)
    assert crypto_blake2b_final(ctx) == digest


@given(MSG, CHUNK_SIZE)
def test_crypto_sha512(msg, chunk_size):
    digest = crypto_sha512(msg)
    ctx = crypto_sha512_init()

    for chunk in chunked(msg, chunk_size):
        crypto_sha512_update(ctx, chunk)
    assert crypto_sha512_final(ctx) == digest


@given(MSG, SHA512_KEY, CHUNK_SIZE)
def test_crypto_hmac_sha512(msg, key, chunk_size):
    digest = crypto_hmac_sha512(msg, key)
    ctx = crypto_hmac_sha512_init(key)

    for chunk in chunked(msg, chunk_size):
        crypto_hmac_sha512_update(ctx, chunk)
    assert crypto_hmac_sha512_final(ctx) == digest


# check that we are calling sha512 correctly!
@given(MSG)
@example(b'')
def test_crypto_sha512_against_stdlib(msg):
    assert crypto_sha512(msg) == hashlib.sha512(msg).digest()


# check that we are calling hmac-sha512 correctly!
@given(binary(), binary())
@example(b'', b'')
def test_crypto_hmac_sha512_against_stdlib(secret, msg):
    assert crypto_hmac_sha512(msg, secret) == hmac.new(secret, msg, hashlib.sha512).digest()


# test vectors
def test_crypto_blake2b_vectors():
    for vec in get_vectors('blake2-kat.json'):
        if vec['hash'] == 'blake2b':
            msg = bytearray.fromhex(vec['in'])
            key = bytes(bytearray.fromhex(vec['key']))
            out = bytes(bytearray.fromhex(vec['out']))
            assert crypto_blake2b(msg, key=key) == out


# Check that we can use bytes-like objects
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
