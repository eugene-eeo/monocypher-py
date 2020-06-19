Digital Signatures
==================

Digital signatures are somewhat similar to signatures in real life;
a verified signature proves to the verifier that at some point, the
document was signed by someone with knowledge of the private key.

.. code:: python

   from monocypher.signing import SigningKey

   # Generate a random SigningKey -- this must be kept secret
   signing_key = SigningKey.generate()
   # This can be published
   verify_key = signing_key.verify_key

   signed = alice_sk.sign(b'hello there!')

Verifying signatures:

.. code:: python

   assert verify_key.verify(signed)

   # You can also verify the detached signature
   assert signed.msg == message
   assert verify_key.verify(message, sig=signed.sig)

Reference
---------

.. module:: monocypher.signing

.. autoclass:: monocypher.signing.SigningKey
   :members:

   .. method:: encode()

      Return the signing key as bytes.

      :rtype: :py:class:`~bytes`

.. autoclass:: monocypher.signing.VerifyKey
   :members:

   .. method:: encode()

      Return the verifying key as bytes.

      :rtype: :py:class:`~bytes`

.. autoclass:: monocypher.signing.SignedMessage
   :members:

.. autoexception:: monocypher.signing.SignatureError


Extras
------

The :py:class:`~monocypher.signing.SigningKey` and :py:class:`~monocypher.signing.VerifyKey`
classes both implement equality (between objects of the same type)
and conversion to :py:class:`bytes`, as well as hashing::

    >>> sk_1 = SigningKey.generate()
    >>> sk_2 = SigningKey.generate()
    >>> sk_1 == sk_2
    False
    >>> sk_1.verify_key == VerifyKey(bytes(sk_1.verify_key))
    True
    >>> hash(sk_1)
    ...
    >>> hash(sk_1.verify_key)
    ...


Implementation
--------------

:py:func:`~monocypher.signing.SigningKey.sign` and :py:func:`~monocypher.signing.VerifyKey.verify`
both use PureEdDSA with Curve25519 and Blake2b, (RFC 8032).
This is the same as Ed25519 with Blake2b instead of SHA-512.

:py:func:`~monocypher.signing.SigningKey.to_private_key` and :py:func:`~monocypher.signing.VerifyKey.to_public_key`
use the ``crypto_from_eddsa_private`` and ``crypto_from_eddsa_public``
functions from Monocypher respectively, which converts from
EdDSA keys to X25519 keys.
