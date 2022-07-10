from monocypher.utils import ensure_length
#from monocypher.public import PublicKey, PrivateKey
from monocypher._monocypher import lib, ffi

#int
#crypto_curve_to_hidden(uint8_t hidden[32], const uint8_t curve[32], uint8_t tweak)
#def curve_to_hidden(your_pk:PublicKey, tweak:bytes) -> Optional[bytes]:
def crypto_curve_to_hidden(your_pk:bytes, tweak:int):
    ensure_length('your_pk', your_pk, 32)

    curve = ffi.from_buffer('uint8_t[32]', your_pk)
    hidden = ffi.new('uint8_t[32]')

    if 0 != lib.crypto_curve_to_hidden(hidden, curve, tweak):
        return None # unsuitable for hiding
    return bytes(hidden)


#void
#crypto_hidden_to_curve(uint8_t curve[32], const uint8_t hidden[32]);
#def hidden_to_curve(your_hidden_pk:bytes) -> PublicKey:
def crypto_hidden_to_curve(your_hidden_pk:bytes) -> bytes:
    ensure_length('your_hidden_pk', your_hidden_pk, 32)

    hidden = ffi.from_buffer('uint8_t[32]', your_hidden_pk)
    pk = ffi.new('uint8_t[32]')

    lib.crypto_hidden_to_curve(pk, hidden)
#    return PublicKey(bytes(pk))
    return bytes(pk)


#void
#crypto_hidden_key_pair(uint8_t hidden[32], uint8_t secret_key[32], uint8_t seed[32]);
#def hidden_key_pair(your_secret_seed:bytes) -> Tuple[bytes, PrivateKey]:
def crypto_hidden_key_pair(your_secret_seed:bytes):
    ensure_length('your_secret_seed', your_secret_seed, 32)

    seed = ffi.from_buffer('uint8_t[32]', your_secret_seed)
    sk = ffi.new('uint8_t[32]')
    hidden_pk = ffi.new('uint8_t[32]')

    lib.crypto_hidden_key_pair(hidden_pk, sk, seed)
#    return bytes(hidden_pk), PrivateKey(bytes(sk))
    return bytes(hidden_pk), bytes(sk)
