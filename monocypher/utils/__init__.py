def ensure(cond, exc, *args):
    if not cond:
        raise exc(*args)


def ensure_bytes_with_length(name, value, length):
    ensure(
        isinstance(value, bytes) and len(value) == length,
        TypeError,
        f'{name} must be bytes with length {length}',
    )
