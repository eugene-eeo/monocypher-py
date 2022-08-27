from hypothesis import given
from hypothesis.strategies import binary
from pytest import raises
from monocypher.utils import random
from monocypher.public import PublicKey, PrivateKey, Box
from monocypher.bindings.crypto_hidden import crypto_curve_to_hidden, crypto_hidden_to_curve, crypto_hidden_key_pair

SEED = binary(min_size=31,max_size=33)
BLIND = binary(min_size=32, max_size=32)

@given(SEED, BLIND)
def test_gen_unhide_hide(seed, blind):
    try:
        hidden_pk, sk = crypto_hidden_key_pair(seed)
    except TypeError as e:
        assert str(e) == 'your_secret_seed must have length 32'
        return
    assert len(seed) == 32

    unhidden_pk = crypto_hidden_to_curve(hidden_pk)

    # we don't know the order used to compute the unhidden pk, so to test
    # that it's compatible we compute
    #   DH(blind_sk, pk)
    #   DH(blind_sk, unhidden_pk)
    blind_sk = PrivateKey(blind)
    box_direct   = Box(blind_sk, PrivateKey(sk).public_key)
    box_unhidden = Box(blind_sk, PublicKey(unhidden_pk))
    assert box_direct.shared_key == box_unhidden.shared_key

    # Elligator2 maps a point to a 254-bit representative indistinguishable
    # from uniformly random bits (with a negliby small bias), but the upper
    # two bits of our 256-bit values are always 0, so the 256-bit values the
    # user operates on are statistically recognizable (by looking at these
    # two bits). To work around that problem, the Monocypher library copies
    # the two upper bits of the 8-bit "tweak" into bits 254 and 255.
    # For the purpose of this test we need to reconstruct the original
    # "tweak" argument by carving these two padding bits out from the 256-bit
    # value:
    tweak = (hidden_pk[31] & 0b11000000)
    # we don't know which representative we got, the lower bit of the tweak
    # selects the negative/positive (can't remember which is which).
    # we compute both and check which one matches:
    rehidden_pk0 = crypto_curve_to_hidden(unhidden_pk, tweak)
    rehidden_pk1 = crypto_curve_to_hidden(unhidden_pk, tweak|1)
    if hidden_pk == rehidden_pk0:
        rehidden_pk = rehidden_pk0
    else:
        assert hidden_pk == rehidden_pk1
        rehidden_pk = rehidden_pk1


def test_vector1():
    '''Generated manually with a C program using libMonocypher'''
    seed = b'\xec\x9b\x04\xcf\x0b\x43\xf5\xd9\x05\x20\x8d\xbc\xc8\x10\xe8\x59\x22\xa2\xaa\x7b\x73\xf6\xcf\x54\x64\x41\x41\x3d\xfc\xbe\x45\xbd'
    hidden_to_curve = b'\xc0\xcb\x33\x08\xef\x16\x76\x7b\x35\xf5\x73\xf1\x53\x39\xbb\x55\xaa\xe9\x89\xb5\x01\x1e\x58\x55\xdd\x08\xde\x0f\x16\xdf\xfa\x62'
    curve_to_hidden = b'\xec\x9b\x04\xcf\x0b\x43\xf5\xd9\x05\x20\x8d\xbc\xc8\x10\xe8\x59\x22\xa2\xaa\x7b\x73\xf6\xcf\x54\x64\x41\x41\x3d\xfc\xbe\x45\x3d'
    tweak = 6
    curve = crypto_hidden_to_curve(seed)
    assert curve == hidden_to_curve
    recovered = crypto_curve_to_hidden(curve, 6)
    assert recovered == curve_to_hidden
