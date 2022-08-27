from monocypher.utils import ensure_length
from monocypher._monocypher import lib, ffi


def crypto_curve_to_hidden(your_pk, tweak):
    ensure_length('your_pk', your_pk, 32)

    curve = ffi.from_buffer('uint8_t[32]', your_pk)
    hidden = ffi.new('uint8_t[32]')

    if lib.crypto_curve_to_hidden(hidden, curve, tweak): # pragma: no cover
        return None # unsuitable for hiding
    return bytes(hidden)


def crypto_hidden_to_curve(your_hidden_pk):
    ensure_length('your_hidden_pk', your_hidden_pk, 32)

    hidden = ffi.from_buffer('uint8_t[32]', your_hidden_pk)
    pk = ffi.new('uint8_t[32]')

    lib.crypto_hidden_to_curve(pk, hidden)
    return bytes(pk)


def crypto_hidden_key_pair(your_secret_seed):
    ensure_length('your_secret_seed', your_secret_seed, 32)

    seed = ffi.from_buffer('uint8_t[32]', your_secret_seed)
    sk = ffi.new('uint8_t[32]')
    hidden_pk = ffi.new('uint8_t[32]')

    lib.crypto_hidden_key_pair(hidden_pk, sk, seed)
    return bytes(hidden_pk), bytes(sk)
