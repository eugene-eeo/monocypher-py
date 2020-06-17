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

.. autoclass:: monocypher.secret.EncryptedMessage
   :members:

.. autoexception:: monocypher.secret.CryptoError
   :members:
