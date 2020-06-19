import os
import json
from itertools import zip_longest


def hex2bytes(b):
    return bytes(bytearray.fromhex(b))


vectors = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors')


def get_vectors(name):
    with open(os.path.join(vectors, name), 'r') as f:
        return json.load(f)


def chunked(bs, n):
    args = [iter(bs)] * n
    for x in zip_longest(*args, fillvalue=None):
        x = [u for u in x if u is not None]
        if x:
            yield bytes(x)
