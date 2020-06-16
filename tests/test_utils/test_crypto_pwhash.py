from hypothesis import given
from hypothesis.strategies import binary, integers
from monocypher.utils.crypto_pwhash import crypto_argon2i


PASSWORD      = binary()
SALT          = binary(min_size=8)
HASH_SIZE     = integers(min_value=1, max_value=128)
NB_BLOCKS     = integers(min_value=8, max_value=4096)
NB_ITERATIONS = integers(min_value=1, max_value=5)
KEY           = binary()
AD            = binary()


@given(PASSWORD, SALT, HASH_SIZE, NB_BLOCKS, NB_ITERATIONS, KEY, AD)
def test_crypto_argon2i(password, salt, hash_size, nb_blocks, nb_iterations, key, ad):
    crypto_argon2i(password,
                   salt,
                   hash_size,
                   nb_blocks,
                   nb_iterations,
                   key,
                   ad)
