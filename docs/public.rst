Key Exchange
============

Key Exchange can be used to exchange a shared key that only the two parties
know (so that they can communicate using symmetric encryption),
without revealing their respective private keys.

.. code:: python

   from monocypher.public import PrivateKey, Box

   # Alice generates a private key; this must be kept secret!
   sk_alice = PrivateKey.generate()
   # This can be sent to anyone (in particular, Bob).
   pk_alice = sk_alice.public_key

   # Bob generates a private key, and sends his public key to Alice.
   sk_bob = PrivateKey.generate()
   pk_bob = sk_bob.public_key

   # Bob and Alice can exchange keys --
   #  1. Alice gives Bob her public key,
   #  2. Bob gives Alice his public key.
   box_bob   = Box(sk_bob, pk_alice)
   box_alice = Box(sk_alice, pk_bob)

   # They then both have the same key:
   assert box_bob.shared_key() == box_alice.shared_key()


A random nonce is automatically generated if not specified.
Alternatively you can specify an explicit nonce.
It does not have to be secret or random, but has to be unique.
Using the same nonce twice with the same encryption key may allow decryption
and forgeries.


.. code:: python

   message = b"Hello there!"

   # Automatically generated nonce:
   encrypted = box_bob.encrypt(message)
   assert box_alice.decrypt(encrypted) == b"Hello there!"

   # Explicitly generated nonce:
   import os
   nonce = os.urandom(Box.NONCE_SIZE)
   encrypted = box_bob.encrypt(message, nonce)
   assert box_alice.decrypt(encrypted) == b"Hello there!"


The above methods perform `authenticated` encryption using key-exchange;
this means that the messages sent can be proven to be sent by you.
If we want the receipient to be unable to verify the identity of the sender
(but still ensure that the message wasn't tampered with),
we use :py:class:`~monocypher.public.SealedBox`:

.. code:: python

   from monocypher.public import SealedBox

   sbox_alice = SealedBox(pk_bob)
   # once we encrypt this message, we are unable to decrypt the resulting
   # ciphertext, even though we created it.
   ciphertext = sbox_alice.encrypt(b'the sequels are better')

   # bob receives this ciphertext and decrypts it using his private key.
   sbox_bob = SealedBox(sk_bob)
   assert sbox_bob.decrypt(ciphertext) == b'the ...'


Reference
---------

.. module:: monocypher.public

.. autoclass:: monocypher.public.PrivateKey
   :members:

   .. data:: KEY_SIZE

      Length of a private key (in bytes).

   .. method:: encode()

      Return the private key as bytes.

      :rtype: :py:class:`~bytes`


.. autoclass:: monocypher.public.PublicKey
   :members:

   .. data:: KEY_SIZE

      Length of a public key (in bytes).

   .. method:: encode()

      Return the public key as bytes.

      :rtype: :py:class:`~bytes`


.. autoclass:: monocypher.public.Box
   :members:
   :inherited-members:


.. autoclass:: monocypher.public.SealedBox
   :members:


Implementation
--------------

:py:class:`~monocypher.public.Box` uses ``crypto_key_exchange`` from Monocypher,
which uses X25519 and HChaCha20.
:py:class:`~monocypher.public.SealedBox` uses the :py:class:`~monocypher.public.Box`
internally, and the encryption format is as follows::

   ephemeral_pk || box(ephemeral_sk, receipient_pk, nonce=(24 zeroes))
