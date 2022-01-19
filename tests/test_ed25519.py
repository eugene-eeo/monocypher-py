from monocypher.bindings import (
    crypto_ed25519_public_key,
    crypto_ed25519_sign,
    crypto_ed25519_check,
    crypto_from_ed25519_private,
    crypto_from_ed25519_public,
)

# RFC 8032 TEST 3 vectors
EDSK = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
EDPK = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
MESSAGE = bytes.fromhex("af82")
SIGNATURE = bytes.fromhex(
    "6291d657deec24024827e69c3abe01a3"
    "0ce548a284743a445e3680d7db5ac3ac"
    "18ff9b538d16f290ae67f760984dc659"
    "4a7c15e9716ed28dc027beceea1ec40a"
)

# EDPK/EDSK converted by libsodium to Curve25519
# Note: bit 255 forced on and 254 forced off on SK to undo the clamping
# done by Sodium because Monocypher does no clamping. The low three
# bits are also clamped but happened to be already zeroes by accident
# with this particular test vector.
PK = bytes.fromhex("cbb22fc9f790bd3eba9b84680c157ca4950a9894362601701f89c3c4d9fda23a")
SK = bytes.fromhex("909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea99c")


def test_ed25519():
    edpk = crypto_ed25519_public_key(EDSK)
    assert edpk.hex() == EDPK.hex()
    signature = crypto_ed25519_sign(EDSK, MESSAGE)
    assert signature.hex() == SIGNATURE.hex()
    valid = crypto_ed25519_check(SIGNATURE, EDPK, MESSAGE)
    assert valid
    valid = crypto_ed25519_check(SIGNATURE, EDPK, b"fakemsg")
    assert not valid


def test_ed25519_to_curve25519():
    sk = crypto_from_ed25519_private(EDSK)
    assert sk.hex() == SK.hex()
    pk = crypto_from_ed25519_public(EDPK)
    assert pk.hex() == PK.hex()
