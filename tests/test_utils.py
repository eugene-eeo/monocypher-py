from monocypher.utils import Encodable, HashEq32


class Enc(Encodable):
    def __init__(self, b):
        self._b = b

    def __bytes__(self):
        return self._b


class HEQ(HashEq32):
    def __init__(self, b):
        self._b = b

    def __bytes__(self):
        return self._b


def test_encodable():
    enc = Enc(b'abc')
    assert enc.encode() == b'abc'


def test_hasheq32():
    enc = HEQ(bytes(32))
    # hashable
    hash(enc)

    assert enc == HEQ(bytes(32))
    assert enc != 1  # No TypeError / NotImplementedError is raised
