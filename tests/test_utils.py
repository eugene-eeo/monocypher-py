from monocypher.utils import Key


class MyKey(Key):
    def __init__(self, b):
        self._b = b

    def __bytes__(self):
        return self._b


def test_key():
    enc = MyKey(bytes(32))
    assert enc.encode() == bytes(32)

    # hashable
    hash(enc)

    assert enc == MyKey(bytes(32))
    assert enc != 1  # No TypeError / NotImplementedError is raised
