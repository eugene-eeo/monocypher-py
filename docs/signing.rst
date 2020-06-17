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

.. autoclass:: monocypher.signing.VerifyKey
   :members:

.. autoclass:: monocypher.signing.SignedMessage
   :members:

.. autoexception:: monocypher.signing.SignatureError


Implementation
--------------

:py:func:`~monocypher.signing.SigningKey.sign` and :py:func:`~monocypher.signing.VerifyKey.verify`
both use PureEdDSA with Curve25519 and Blake2b, (RFC 8032).
This is the same as Ed25519 with Blake2b instead of SHA-512.
