from hypothesis import given
from hypothesis.strategies import binary
from monocypher.bindings import crypto_wipe


@given(binary())
def test_crypto_wipe(msg):
    b = bytearray(msg)
    crypto_wipe(b)
    assert bytes(b) == bytes(len(msg))
