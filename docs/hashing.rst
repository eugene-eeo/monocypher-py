Hashing
=======

The Blake2b cryptographic hash function is the preferred one -- it is faster
than MD5 yet just as secure as SHA-3. Note that for password hashing or deriving
keys from passwords, please use a PDKF like Argon2.

.. module:: monocypher.hash

.. function:: monocypher.hash.blake2b(msg, key=b'', hash_size=64)

   Computes the Blake2b digest of the given `msg`,
   optionally with a `key` (which can be used to construct a
   message authentication code). The returned digest will
   have length `hash_size`.

   :param msg: The message (a bytes-like object).
   :param key: The key (:py:class:`~bytes`), between :py:obj:`.KEY_MIN` and :py:obj:`.KEY_MAX` long.
   :param hash_size: Digest length (:py:class:`~int`), between :py:obj:`.HASH_MIN` and :py:obj:`.HASH_MAX`.
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


.. function:: monocypher.hash.sha512(msg)

   Computes the SHA512 digest of the given `msg`, a bytes-like object.

   :rtype: :py:class:`~bytes`

HMAC-SHA512
-----------

.. function:: monocypher.hash.hmac_sha512(msg, key)

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
           ctx.update(chunk)
   digest = ctx.digest()


.. autoclass:: monocypher.hash.Context
   :members:

   Can be used to incrementally compute the hash of a long
   stream of bytes (e.g. a large file) without having to read
   all of it into memory.

.. autoclass:: monocypher.hash.Blake2bContext

   `key` and `hash_size` have the same meaning as those from
   :py:func:`~monocypher.hash.blake2b`.

   .. data:: KEY_MIN

      minimum key length

   .. data:: KEY_MAX

      maximum key length

   .. data:: HASH_MIN

      minimum digest length

   .. data:: HASH_MAX

      maximum digest length

.. autoclass:: monocypher.hash.SHA512Context
   :members:

.. autoclass:: monocypher.hash.HMACSHA512Context
   :members:

   `key` has the same meaning as that from
   :py:func:`~monocypher.hash.hmac_sha512`.
