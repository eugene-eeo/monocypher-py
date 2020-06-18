import pytest
from pytest import raises
from monocypher.utils import random
from monocypher.bindings import crypto_blake2b, crypto_sha512, crypto_hmac_sha512
from monocypher.hash import Blake2bContext, SHA512Context, HMACSHA512Context


@pytest.mark.parametrize('fn, context, args', [
    [crypto_blake2b,     Blake2bContext,    {'key': random(24), 'hash_size': 64}],
    [crypto_sha512,      SHA512Context,     {}],
    [crypto_hmac_sha512, HMACSHA512Context, {'key': random(256)}],
])
def test_blake2b_context(fn, context, args):
    digest = fn(msg=b'abc', **args)
    ctx = context(**args)
    ctx.update(b'a')
    ctx.update(b'b')
    ctx.update(b'c')

    assert ctx.digest() == digest

    # we have already finalised!
    with raises(RuntimeError):
        ctx.update(b'more data')
