from monocypher._monocypher import ffi


def ensure(cond, exc, *args):
    if not cond:
        raise exc(*args)


def ensure_bytes(name, value):
    ensure(
        isinstance(value, bytes),
        TypeError,
        f'{name} must be bytes',
    )


def ensure_bytes_with_length(name, value, length):
    ensure(
        isinstance(value, bytes) and len(value) == length,
        TypeError,
        f'{name} must be bytes with length {length}',
    )


def ensure_range(name, value, min, max):
    ensure(
        isinstance(value, int) and (min <= value <= max),
        TypeError,
        f'{name} must be an integer between {min} and {max}',
    )


def ensure_context(name, value, type, how):
    ensure(
        ffi.typeof(value).cname == type,
        TypeError,
        f'{name} should be from {how}'
    )


class Encodable:
    def encode(self):
        return bytes(self)
