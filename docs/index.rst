``monocypher-py``
=================

``monocypher-py`` provides both high-level APIs (similar to `PyNaCl <https://pynacl.readthedocs.io/>`_)
and low-level bindings to the `Monocypher <https://monocypher.org/>`_ library.
Monocypher is a small, fast, easy to deploy, and easy to use cryptography library.
It supports Python 3.5+ (including PyPy).

Installation
------------

``monocypher-py`` bundles Monocypher 3.1.0 along with the source.

::

   $ pip install monocypher-py

Features
--------

* Authenticated Encryption (XChacha20 + Poly1305)
* Hashing and Message Authentication (Blake2b, SHA-512, HMAC-SHA-512)
* Password key derivation and hashing (Argon2i)
* Key Exchange (X25519)
* Digital Signatures (EdDSA with Blake2b and Ed25519)


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


* :ref:`genindex`
* :ref:`modindex`
