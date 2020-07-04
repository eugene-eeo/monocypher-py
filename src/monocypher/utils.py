import os
from monocypher._monocypher import ffi


__all__ = (
    'random',
    'copy_context',
    'crypto_wipe',
    'crypto_verify16',
    'crypto_verify32',
    'crypto_verify64',
    'ensure',
)


def random(n):
    """
    Generates exactly `n` random bytes.
    This just calls :py:func:`os.urandom` and returns the result.

    :rtype: :py:class:`bytes`
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
    dst_void = ffi.cast('uint8_t *', dst_ptr)
    ctx_void = ffi.cast('uint8_t *', ctx_ptr)
    ffi.memmove(
        dst_void,
        ctx_void,
        ffi.sizeof(ctx_ptr[0]),
    )
    return dst_ptr


def ensure(cond, exc, *args):
    if not cond:
        raise exc(*args)


def ensure_length(name, value, length):
    ensure(
        len(value) == length,
        TypeError,
        '{} must have length {}'.format(name, length),
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


class Key:
    __slots__ = ()

    def encode(self):
        return bytes(self)

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return crypto_verify32(bytes(self), bytes(other))


from monocypher.bindings.crypto_utils import crypto_wipe, crypto_verify16, crypto_verify32, crypto_verify64  # noqa: E402
