.. highlight:: python

Bindings
========

Refer to the `Monocypher manual <https://monocypher.org/manual/>`_
for details on the arguments. They are one-to-one mappings and
return the expected values, e.g. ``crypto_check`` returns a
boolean representing whether the signature is valid, ``crypto_verify16``
returns whether the two byte strings match, etc. Additionally they are
easier to use since you don't have to pass in the accompanying length
for each parameter.

All parameters which are expected to be ``uint8_t[]`` or ``uint8_t[K]``
in the Monocypher API can receive a
`bytes-like object <https://docs.python.org/3/glossary.html#term-bytes-like-object>`_
as input. In particular this means you can wipe secrets::

   secret_key = bytearray(32)
   open('secret.txt', mode='rb').readinto(secret_key)

   crypto_sign(secret_key, b'hello world!')
   crypto_wipe(secret_key)
   assert bytes(secret_key) == bytes(32)

However, there are some pitfalls in the name of convenience -- e.g.,
if you use :py:func:`~monocypher.bindings.crypto_from_ed25519_private`,
it returns a :py:class:`bytes` object containing the derived X25519
private key -- if you need that much control over memory, you probably
know what you're doing anyways.

.. automodule:: monocypher.bindings
   :members:
   :undoc-members:
