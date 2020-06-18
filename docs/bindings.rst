Bindings
========

Refer to the `Monocypher manual <https://monocypher.org/manual/>`_
for details on the arguments. They are one-to-one mappings and
return the expected values, e.g. ``crypto_check`` returns a
boolean representing whether the signature is valid, ``crypto_verify16``
returns whether the two byte strings match, etc. Additionally they are
easier to use since you don't have to pass in the accompanying length
for each parameter.

For parameters which can have unbounded length (except for ``key``,
``salt``, and arguments to :py:func:`~monocypher.bindings.crypto_argon2i`),
you can pass in a `bytes-like object <https://docs.python.org/3/glossary.html#term-bytes-like-object>`_,
unless mentioned otherwise. Otherwise, you need to pass in a
:py:class:`~bytes` object with the correct length.

.. automodule:: monocypher.bindings
   :members:
   :undoc-members:
