# monocypher-py

Python bindings for [Monocypher](https://monocypher.org/) 3.1.0 using the cffi library.
Monocypher is a small, fast, easy to deploy, and easy to use cryptography library.
monocypher-py provides both high- (a-la [PyNaCl](https://pynacl.readthedocs.io/en/stable/))
and low-level APIs around Monocypher.
There is no aim for drop-down compatibility with PyNaCl (especially since Monocypher uses
different primitives compared to NaCl).

### high-level api

```python
>>> from monocypher.public import PrivateKey, Box
>>> sk_a = PrivateKey.generate()
>>> sk_b = PrivateKey.generate()
>>> box = Box(sk_a, sk_b.public_key)
>>> box.encrypt(b'hello world!')
b'\xdbZn...'
```

### low-level api

```python
>>> import monocypher.bindings as mc
>>> sk_a_bytes = sk_a.encode()
>>> pk_b_bytes = sk_b.public_key.encode()
>>> shared_key = mc.crypto_key_exchange(sk_a_bytes, pk_b_bytes)
>>> box.shared_key() == shared_key
True
```
