``monocypher-py``
=================

``monocypher-py`` provides both high-level APIs (similar to `PyNaCl <https://pynacl.readthedocs.io/>`_)
and low-level bindings to the `Monocypher <https://monocypher.org/>`_ library.
Monocypher is a small, fast, easy to deploy, and easy to use cryptography library.
It supports Python 3.5+ (including PyPy). Examples::

   >>> # high-level api
   >>> from monocypher.public import PrivateKey, Box
   >>> sk_a = PrivateKey.generate()
   >>> sk_b = PrivateKey.generate()
   >>> box = Box(sk_a, sk_b.public_key)
   >>> box.encrypt(b'hello world!')
   b'\xdbZn...'

   >>> # low-level api
   >>> import monocypher.bindings as mc
   >>> sk_a_bytes = sk_a.encode()
   >>> pk_b_bytes = sk_b.public_key.encode()
   >>> shared_key = mc.crypto_key_exchange(sk_a_bytes, pk_b_bytes)
   >>> box.shared_key() == shared_key
   True

Installation
------------

``monocypher-py`` bundles Monocypher 3.1.1 (with the optional code)
along with the source.

::

   $ pip install monocypher-py

User Guide
----------

.. toctree::
   :maxdepth: 1

   public
   secret
   hashing
   signing
   pwhash
   utils
   bindings

Indices and tables
------------------
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
