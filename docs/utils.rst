Utilities
=========

.. module:: monocypher.utils


Generating Random Bytes
-----------------------

.. autofunction:: monocypher.utils.random


Constant-Time Comparisons
-------------------------

The following functions perform constant-time comparisons of :py:class:`~bytes`
objects of length 16, 32, and 64 respectively. They return ``True`` if they
are equal, and ``False`` otherwise.

.. autofunction:: monocypher.utils.crypto_verify16

.. autofunction:: monocypher.utils.crypto_verify32

.. autofunction:: monocypher.utils.crypto_verify64

.. code:: python

   from monocypher.utils import crypto_verify16
   crypto_verify16(b'a....a', b'a....a')


Copying Contexts
----------------

.. autofunction:: monocypher.utils.copy_context
