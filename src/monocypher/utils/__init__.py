import os
from monocypher._monocypher import ffi


def random(n):
    return os.urandom(n)


def ensure(cond, exc, *args):
    if not cond:
        raise exc(*args)


def ensure_bytes(name, value):
    ensure(
        isinstance(value, bytes),
        TypeError,
        '{} must be bytes'.format(name),
    )


def ensure_bytes_with_length(name, value, length):
    ensure(
        isinstance(value, bytes) and len(value) == length,
        TypeError,
        '{} must be bytes with length {}'.format(name, length),
    )


def ensure_range(name, value, min, max=float('+inf')):
    ensure(
        isinstance(value, int) and (min <= value <= max),
        TypeError,
        '{name} must be an integer between {min} and {max}'.format(name=name, min=min, max=max),
    )


def ensure_context(name, value, type, how):
    ensure(
        ffi.typeof(value).cname == type,
        TypeError,
        '{} should be from {}'.format(name, how),
    )


class Encodable:
    __slots__ = ()

    def encode(self):
        return bytes(self)
