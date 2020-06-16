from hypothesis import given
from hypothesis.strategies import binary, one_of, sampled_from, integers
from monocypher.pwhash import pwhash, argon2i, verify


PASSWORD  = binary()
SALT      = one_of(sampled_from([None]), binary(min_size=8, max_size=256))
HASH_SIZE = sampled_from([16, 32, 64])
NB_BLOCKS = integers(min_value=8, max_value=10000)
NB_ITERS  = integers(min_value=1, max_value=10)


@given(PASSWORD, SALT, HASH_SIZE, NB_BLOCKS, NB_ITERS)
def test_pwhash(password, salt, hash_size, nb_blocks, nb_iters):
    assert verify(password, pwhash(
        password,
        salt=salt,
        nb_blocks=nb_blocks,
        nb_iterations=nb_iters,
        hash_size=hash_size,
    ))
