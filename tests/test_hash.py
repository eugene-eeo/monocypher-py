import pytest
from itertools import zip_longest
from hypothesis import given
from hypothesis.strategies import binary, integers
from monocypher.utils import random
from monocypher.bindings import crypto_blake2b, crypto_sha512, crypto_hmac_sha512
from monocypher.hash import Blake2bContext, SHA512Context, HMACSHA512Context


def grouper(iterable, n):
    args = [iter(iterable)] * n
    for x in zip_longest(*args, fillvalue=None):
        x = [u for u in x if u is not None]
        if x:
            yield bytes(x)


@pytest.mark.parametrize('fn, context, args', [
    [crypto_blake2b,     Blake2bContext,    {'key': random(24), 'hash_size': 64}],
    [crypto_sha512,      SHA512Context,     {}],
    [crypto_hmac_sha512, HMACSHA512Context, {'key': random(256)}],
])
@given(binary(), integers(min_value=1, max_value=256))
def test_blake2b_context(fn, context, args, msg, chunk_size):
    msg_size = len(msg)

    msg1 = msg[:msg_size // 2]
    msg2 = msg[msg_size // 2:]

    digest1 = fn(msg=msg1, **args)
    digest2 = fn(msg=msg, **args)

    ctx1 = context(**args)

    for chunk in grouper(msg1, chunk_size):
        ctx1.update(chunk)

    assert ctx1.digest() == digest1

    ctx2 = ctx1.copy()

    for chunk in grouper(msg2, chunk_size):
        ctx2.update(chunk)

    assert ctx1.digest() == digest1
    assert ctx2.digest() == digest2
