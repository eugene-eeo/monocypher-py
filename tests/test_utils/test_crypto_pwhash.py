from hypothesis import given
from hypothesis.strategies import binary, integers
from monocypher.utils.crypto_pwhash import crypto_argon2i

from tests.utils import get_vectors, hex2bytes


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


def test_argon2i_vectors():
    for vec in get_vectors('argon2i-vectors.json'):
        password      = hex2bytes(vec['password'])
        salt          = hex2bytes(vec['salt'])
        hash          = hex2bytes(vec['hash'])
        nb_blocks     = vec['nb_blocks']
        nb_iterations = vec['nb_iterations']
        hash_size     = vec['hash_size']
        assert crypto_argon2i(
            password,
            salt,
            hash_size,
            nb_blocks,
            nb_iterations,
        ) == hash
