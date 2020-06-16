monocypher-py
=============

Python bindings for [Monocypher](https://monocypher.org/) using the cffi library.
Monocypher is a small, fast, easy to deploy, and easy to use library.
`monocypher-py` provides both high-level
(similar to [PyNaCl](https://pynacl.readthedocs.io/en/stable/),
but using Monocypher's higher-level functions instead)
and low-level APIs around Monocypher:

    >>> from monocypher.public import PrivateKey, Box
    >>> sk_a = PrivateKey.generate()
    >>> sk_b = PrivateKey.generate()
    >>> box = Box(sk_a, sk_b.public_key)
    >>> box.encrypt(b'hello world!')
    b'\xdbZn...'

    >>> import monocypher.bindings as mc
    >>> sk_a_bytes = sk_a.encode()
    >>> pk_b_bytes = sk_b.public_key.encode()
    >>> shared_key = mc.crypto_key_exchange(sk_a_bytes, pk_b_bytes)
    >>> box.shared_key() == shared_key
    True

`monocypher-py` is licensed under CC-0. Differences from NaCl
(and by-extension, PyNaCl):

> - Authenticated encryption implements RFC 8439 with XChacha20 and Poly1305. XChacha20 nonces are big enough to be random.
> - Hashing uses Blake2b, which is as secure as SHA-3, and as fast as MD5.
> - Password key derivation is done with Argon2i, which won the [Password Hashing competition](https://password-hashing.net/).
> - Key exchange uses X25519.
> - Signatures use EdDSA (RFC 8032) with Blake2b and edwards25519. Optionally, Blake2b can be replaced by SHA-512 for Ed25519 compatibility.
