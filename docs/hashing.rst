Hashing
=======

The Blake2b cryptographic hash function is the preferred one -- it is faster
than MD5 yet just as secure as SHA-3. Note that for password hashing or deriving
keys from passwords, please use a PDKF like Argon2.

.. module:: monocypher.hash

.. autofunction:: monocypher.hash.blake2b

   Computes the Blake2b digest of the given `msg`,
   optionally with a `key` (which can be used to construct a
   message authentication code). The returned digest will
   have length `hash_size`.

   :param msg: The message (a bytes-like object).
   :param key: The key (bytes-like), between :py:obj:`.Blake2bContext.KEY_MIN` and :py:obj:`.Blake2bContext.KEY_MAX` long.
   :param hash_size: Digest length (:py:class:`int`), between :py:obj:`.Blake2bContext.HASH_MIN` and :py:obj:`.Blake2bContext.HASH_MAX`.
                     When using Blake2b as a MAC, anything below 16 is discouraged,
                     and when using Blake2b as a general-purpose hash function,
                     anything below 32 is discouraged.
   :rtype: :py:class:`bytes`

MAC Example
-----------

.. code:: python

   from monocypher.utils import random, crypto_verify16
   from monocypher.hash import blake2b

   KEY = random(64)

   def compute_mac(msg):
       return blake2b(msg, key=KEY, hash_size=16)

   def verify_mac(msg, mac):
       # Do not use "mac == compute_mac(msg)" here, since
       # we may leak some information about the real mac
       # (see timing attacks).
       return crypto_verify16(mac, compute_mac(msg))


Incremental Interface
---------------------

.. code:: python

   from monocypher.hash import Blake2bContext
   ctx = Blake2bContext()
   with open('file', mode='rb') as f:
       while True:
           chunk = f.read(4096)
           if chunk == b'':
               break
           ctx.update(chunk)
   digest = ctx.digest()


.. autoclass:: monocypher.hash.Blake2bContext
   :members:
