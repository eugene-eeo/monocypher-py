Authenticated Encryption
========================

Authenticated Encryption allows you to make sure that the received ciphertext
hasn't been tampered with by attaching and verifying a MAC (Message Authentication
Code) along with the encrypted ciphertext.

.. code:: python

   from monocypher.utils import random
   from monocypher.secret import SecretBox

   key = random(SecretBox.KEY_SIZE)
   box = SecretBox(key)
   # Automatically generated nonce, similar to Box
   ciphertext = box.encrypt(b'my message')

   # later on ... (key must be the same!)
   box = SecretBox(key)
   assert box.decrypt(ciphertext) == b'my message'


Reference
---------

.. module:: monocypher.secret

.. autoclass:: monocypher.secret.SecretBox
   :members:

   .. automethod:: encode

      Returns the encryption key as :py:class:`bytes`.

      :rtype: :class:`bytes`

.. autoclass:: monocypher.secret.EncryptedMessage
   :members:

.. autoexception:: monocypher.secret.CryptoError
   :members:


Extras
------

The :py:class:`~monocypher.secret.SecretBox` class,
and by extension :py:class:`~monocypher.public.Box`
implements equality (between objects of the same type)
and conversion to :py:class:`bytes`, as well as hashing::

    >>> key = random(SecretBox.KEY_SIZE)
    >>> sbox = SecretBox(key)
    >>> sbox == SecretBox(key)
    False
    >>> bytes(sbox) == key
    True
    >>> hash(sbox)
    ...


Implementation
--------------

:py:class:`~monocypher.secret.SecretBox` uses the 
``crypto_lock`` functions from Monocypher, which
implement RFC 8439 (ChaCha20 and Poly1305 for IETF Protocols),
using XChaCha20 instead of ChaCha20.
