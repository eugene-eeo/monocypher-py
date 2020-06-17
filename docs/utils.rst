Utilities
=========

Generating Random Bytes
-----------------------

.. module:: monocypher.utils

.. autofunction:: monocypher.utils.random

   Generates exactly `n` random bytes.
   This just calls the :py:func:`~os.urandom` function
   and returns the result.

   :rtype: :py:class:`~bytes`


Constant-Time Comparisons
-------------------------

.. module:: monocypher.cmp

The following functions perform constant-time comparisons of :py:class:`~bytes`
objects of length 16, 32, and 64 respectively. They return ``True`` if they
are equal, and ``False`` otherwise.

.. autofunction:: monocypher.cmp.crypto_verify16

.. autofunction:: monocypher.cmp.crypto_verify32

.. autofunction:: monocypher.cmp.crypto_verify64

.. code:: python

   from monocypher.cmp import crypto_verify16
   crypto_verify16(b'a....a', b'a....a')