from monocypher.bindings.crypto_pwhash import crypto_argon2i

from tests.utils import get_vectors, hex2bytes


def test_argon2i_vectors():
    for vec in get_vectors('argon2i-vectors.json'):
        password      = hex2bytes(vec['password'])
        salt          = hex2bytes(vec['salt'])
        ad            = hex2bytes(vec['ad'])
        key           = hex2bytes(vec['key'])
        hash          = hex2bytes(vec['hash'])
        nb_blocks     = vec['nb_blocks']
        nb_iterations = vec['nb_iterations']
        hash_size     = vec['hash_len']
        assert crypto_argon2i(
            password,
            salt,
            hash_size,
            nb_blocks,
            nb_iterations,
            key,
            ad,
        ) == hash
