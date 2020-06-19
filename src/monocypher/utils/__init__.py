import os
from monocypher._monocypher import ffi


def random(n):
    """
    Generates exactly `n` random bytes.
    This just calls the :py:func:`os.urandom` function
    and returns the result.

    :rtype: :py:class:`~bytes`
    """
    return os.urandom(n)


def copy_context(ctx_ptr, type):
    """
    Return a copy of the struct at `ctx_ptr` of the given `type`.
    This can be used to copy structs, e.g. ``crypto_blake2b_ctx``.
    This is equivalent to the following in C:

    .. code:: c

       type dst_ptr = malloc(sizeof(*ctx_ptr));
       memcpy(
           (void *) dst_ptr,
           (void *) ctx_ptr,
           sizeof(*ctx_ptr)
       );

    Example::

        >>> from monocypher.bindings import crypto_blake2b_init
        >>> ctx = crypto_blake2b_init()
        >>> u = copy_context(ctx, 'crypto_blake2b_ctx *')
        <cdata 'crypto_blake2b_ctx *' owning ...>
        >>> u == ctx
        False

    :param ctx_ptr: CFFI pointer to some struct.
    :param type: Type of `ctx_ptr`.
    """
    dst_ptr  = ffi.new(type)
    ctx_void = ffi.cast('uint8_t *', ctx_ptr)
    dst_void = ffi.cast('uint8_t *', dst_ptr)
    ffi.memmove(
        dst_void,
        ctx_void,
        ffi.sizeof(ctx_ptr[0]),
    )
    return dst_ptr


def ensure(cond, exc, *args):
    if not cond:
        raise exc(*args)


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
