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
   :param key: The key (:py:class:`bytes`), between :py:obj:`.Blake2bContext.KEY_MIN` and :py:obj:`.Blake2bContext.KEY_MAX` long.
   :param hash_size: Digest length (:py:class:`int`), between :py:obj:`.Blake2bContext.HASH_MIN` and :py:obj:`.Blake2bContext.HASH_MAX`.
                     When using Blake2b as a MAC, anything below 16 is discouraged,
                     and when using Blake2b as a general-purpose hash function,
                     anything below 32 is discouraged.
   :rtype: :py:class:`~bytes`

MAC Example
-----------

.. code:: python

   from monocypher.hash import blake2b
   from monocypher.cmp import crypto_verify16

   KEY = b'super-secret-key'

   def compute_mac(msg):
       return blake2b(msg, key=KEY, hash_size=16)

   def verify_mac(msg, mac):
       # Do not use "mac == compute_mac(msg)" here, since
       # we may leak some information about the real mac
       # (see timing attacks).
       return crypto_verify16(mac, compute_mac(msg))


SHA-512
-------

SHA-512 is a cryptographically secure hash.
It is generally recommended to use :py:func:`~monocypher.hash.blake2b` instead,
as it is faster on x86_64 CPUs and lacks many of the pitfalls of SHA-512.
SHA-512 cannot be used as a MAC algorithm directly; please use
:py:func:`~monocypher.hash.hmac_sha512` instead.

Note that SHA-512 itself is not suitable for hashing passwords and deriving
keys from them; please use a PDKF like Argon2.


.. autofunction:: monocypher.hash.sha512

   Computes the SHA512 digest of the given `msg`, a bytes-like object.

   :rtype: :py:class:`~bytes`

HMAC-SHA512
-----------

.. autofunction:: monocypher.hash.hmac_sha512

   Computes the HMAC-SHA512 MAC of the given `msg` (a bytes-like object).
   In most cases the MAC can be safely truncated down to 16 bytes
   (but we leave that choice up to the user).

   :param key: The key (:py:class:`~bytes`). 32 is a good default. Keys longer
               than 128 bytes will be reduced to 64 bytes by hashing it with
               SHA-512.
   :rtype: :py:class:`~bytes`


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


.. autoclass:: monocypher.hash.Context
   :members:

.. autoclass:: monocypher.hash.Blake2bContext
   :members:

.. autoclass:: monocypher.hash.SHA512Context()
   :members:

.. autoclass:: monocypher.hash.HMACSHA512Context
   :members:
