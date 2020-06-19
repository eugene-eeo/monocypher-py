.. highlight:: python

Key Exchange
============

Key Exchange can be used to exchange a shared key that only the two parties
know (so that they can communicate using symmetric encryption),
without revealing their respective private keys.

::

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


During encryption, a random nonce is automatically generated if not specified.
Alternatively, you can specify an explicit nonce.
It does not have to be secret or random (for instance, you can just
use the message counter as the nonce in some protocols),
but has to be unique.

.. warning::

   Using the same nonce twice with the same encryption key may allow decryption
   and forgeries.


::

    message = b"Hello there!"

    # Automatically generated nonce:
    encrypted = box_bob.encrypt(message)
    assert box_alice.decrypt(encrypted) == b"Hello there!"

    # Explicitly generated nonce:
    from monocypher.utils import random
    nonce = random(Box.NONCE_SIZE)
    encrypted = box_bob.encrypt(message, nonce)
    assert box_alice.decrypt(encrypted) == b"Hello there!"


The above methods perform authenticated encryption using key-exchange;
this means that the messages sent can be proven to be sent by you.
If we want the receipient to be unable to verify the identity of the sender
(but still ensure that the message wasn't tampered with),
use a :py:class:`~monocypher.public.SealedBox`:

::

    from monocypher.public import SealedBox

    sbox_alice = SealedBox(pk_bob)
    # Once we encrypt this message, we are unable to decrypt the
    # ciphertext, even though we created it.
    ciphertext = sbox_alice.encrypt(b'the sequels are better')

    # Bob can decrypt it using his private key.
    sbox_bob = SealedBox(sk_bob)
    assert sbox_bob.decrypt(ciphertext) == b'the ...'


Reference
---------

.. module:: monocypher.public

.. autoclass:: monocypher.public.PrivateKey
   :members:

   .. method:: encode()

      Return the private key as bytes.

      :rtype: :py:class:`~bytes`


.. autoclass:: monocypher.public.PublicKey
   :members:

   .. method:: encode()

      Return the public key as bytes.

      :rtype: :py:class:`~bytes`


.. autoclass:: monocypher.public.Box
   :members:
   :inherited-members:


.. autoclass:: monocypher.public.SealedBox
   :members:


Extras
------

The :py:class:`~monocypher.public.PrivateKey` and :py:class:`~monocypher.public.PublicKey`
classes both implement equality (between objects of the same type)
and conversion to :py:class:`bytes`, as well as hashing::

    >>> sk_1 = PrivateKey.generate()
    >>> sk_2 = PrivateKey.generate()
    >>> sk_1 == sk_2
    False
    >>> sk_1.public_key == PublicKey(bytes(sk_1.public_key))
    True
    >>> hash(sk_1)
    ...
    >>> hash(sk_1.public_key)
    ...


Implementation
--------------

:py:class:`~monocypher.public.Box`'s key derivation uses ``crypto_key_exchange``
from Monocypher, which uses X25519 and HChaCha20.
:py:class:`~monocypher.public.SealedBox` uses the same algorithm,
and the encryption format is as follows::

   ephemeral_pk || box(ephemeral_sk, receipient_pk, msg, nonce=(24 zeroes))
