import os
import json


def hex2bytes(b):
    return bytes(bytearray.fromhex(b))


vectors = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors')


def get_vectors(name):
    with open(os.path.join(vectors, name), 'r') as f:
        return json.load(f)
