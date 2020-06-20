from hypothesis import given
from hypothesis.strategies import binary
from monocypher.bindings.crypto_utils import crypto_verify16, crypto_verify32, crypto_verify64, crypto_wipe


@given(binary(min_size=16, max_size=16),
       binary(min_size=16, max_size=16))
def test_crypto_verify_16(a, b):
    assert crypto_verify16(a, b) == (a == b)


@given(binary(min_size=32, max_size=32),
       binary(min_size=32, max_size=32))
def test_crypto_verify_32(a, b):
    assert crypto_verify32(a, b) == (a == b)


@given(binary(min_size=64, max_size=64),
       binary(min_size=64, max_size=64))
def test_crypto_verify_64(a, b):
    assert crypto_verify64(a, b) == (a == b)


@given(binary())
def test_crypto_wipe(b):
    size = len(b)
    ba = bytearray(b)
    crypto_wipe(ba)
    assert ba == bytes(size)
