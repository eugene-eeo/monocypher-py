from hypothesis import given
from hypothesis.strategies import binary, integers
from monocypher.utils import random
from monocypher.hash import Blake2bContext, blake2b
from tests.utils import chunked


@given(binary(), integers(min_value=1, max_value=256))
def test_blake2b_context(msg, chunk_size):
    args = {'key': random(24), 'hash_size': 64}
    msg_size = len(msg)

    msg1 = msg[:msg_size // 2]
    msg2 = msg[msg_size // 2:]

    digest1 = blake2b(msg=msg1, **args)
    digest2 = blake2b(msg=msg, **args)

    ctx1 = Blake2bContext(**args)

    for chunk in chunked(msg1, chunk_size):
        ctx1.update(chunk)

    assert ctx1.digest() == digest1

    ctx2 = ctx1.copy()

    for chunk in chunked(msg2, chunk_size):
        ctx2.update(chunk)

    assert ctx1.digest() == digest1
    assert ctx2.digest() == digest2
