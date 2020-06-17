Password Hashing
================

Password Hashing is done via the Argon2i PDKF.
PDKFs can be used for password checking, or key derivation (e.g. implementing
encryption with a password).
The output is suitable for use as the key for the :py:class:`~monocypher.secret.SecretBox`.

.. module:: monocypher.pwhash

.. autofunction:: monocypher.pwhash.argon2i

   Computes the raw Argon2i (with a parallelism value = 1) hash,
   given the `password` and `salt`.

   If you want to use the output for password verification, it is
   recommended to set the `hash_size` to 32 or 64 so that you can
   use the :py:func:`monocypher.cmp.crypto_verify32` or
   :py:func:`monocypher.cmp.crypto_verify64` functions.

   :param password: Password (:py:class:`bytes`).
   :param salt: Salt (:py:class:`bytes`), at least 8 bytes.
   :param nb_blocks: Memory cost in KiB; >= 8. (:py:class:`int`)
   :param nb_iterations: Time cost; >= 1. (:py:class:`int`)
   :param hash_size: Length of hash in bytes, >= 4. (:py:class:`int`)
   :param key: Optional key (:py:class:`bytes`).
   :param ad: Optional additional data (:py:class:`bytes`)
   :rtype: :py:class:`bytes`

Key Derivation
--------------

.. code:: python

   from monocypher.pwhash import argon2i
   from monocypher.secret import SecretBox

   key = argon2i(b'hunter2', b'super-secret-salt', hash_size=32)
   box = SecretBox(key)
   box.encrypt(b'doesnt look like stars to me')

Password Verification
---------------------

.. note::

   You should consider using another library like `argon2-cffi <https://argon2-cffi.readthedocs.io/en/stable/>`_
   for verification in most serious use cases (e.g. when making
   web applications), since it can produce and verify hashes in
   the `Argon2 PHC format <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md>`_.

.. code:: python

   from monocypher.pwhash import argon2i
   from monocypher.cmp import crypto_verify32

   salt = b'super-secret-salt'

   def hash_password(password):
       return argon2i(password, b'super-secret-salt', hash_size=32)

   # store somewhere
   digest = hash_password(b'hunter2')

   # verification
   password = input().encode('utf-8')
   if not crypto_verify32(hash_password(password), digest):
       reject_user()
