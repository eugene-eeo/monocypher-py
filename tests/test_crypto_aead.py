from hypothesis import given
from hypothesis.strategies import binary
from monocypher.utils.crypto_aead import crypto_lock, crypto_unlock
from monocypher._monocypher import ffi, lib


KEY   = binary(min_size=32, max_size=32)
NONCE = binary(min_size=24, max_size=24)
MAC   = binary(min_size=16, max_size=16)
MSG   = binary()
AD    = binary()


@given(KEY, NONCE, MSG)
def test_crypto_lock_equivalent(key, nonce, msg):
    # we expose the more general crypto_lock_aead()
    # function, so check if we are calling it the right way
    # when ad == b''
    original_message = msg
    aead_mac, _, aead_ct = crypto_lock(key, nonce, msg)

    msg_size = len(msg)
    mac   = ffi.new('uint8_t[16]')
    key   = ffi.new('uint8_t[32]', key)
    nonce = ffi.new('uint8_t[24]', nonce)
    msg   = ffi.new('uint8_t[]', msg)
    ct    = ffi.new('uint8_t[]', bytes(msg_size))
    lib.crypto_lock(
        mac, ct, key, nonce,
        msg, msg_size
    )
    assert bytes(mac) == aead_mac
    assert bytes(ct)[:-1] == aead_ct

    # check that we can decrypt this
    lib.crypto_wipe(msg, msg_size)
    rv = lib.crypto_unlock(msg, key, nonce, mac, ct, msg_size)
    assert rv == 0
    assert bytes(msg)[:-1] == original_message


@given(KEY, NONCE, MSG, AD)
def test_crypto_lock(key, nonce, msg, additional_data):
    mac, nonce2, ct = crypto_lock(key, nonce, msg, additional_data)
    assert nonce2 == nonce
    assert crypto_unlock(key, mac, nonce, ct, additional_data) == msg


@given(KEY, NONCE, MSG, MAC)
def test_crypto_lock_mac(key, nonce, msg, mac2):
    mac, _, ct = crypto_lock(key, nonce, msg)
    if mac != mac2:
        assert crypto_unlock(key, mac2, nonce, ct) is None


@given(KEY, NONCE, MSG, NONCE)
def test_crypto_lock_nonce(key, nonce, msg, nonce2):
    mac, _, ct = crypto_lock(key, nonce, msg)
    if nonce != nonce2:
        assert crypto_unlock(key, mac, nonce2, ct) is None


@given(KEY, NONCE, MSG, KEY)
def test_crypto_lock_key(key, nonce, msg, key2):
    mac, _, ct = crypto_lock(key, nonce, msg)
    if key != key2:
        assert crypto_unlock(key2, mac, nonce, ct) is None
