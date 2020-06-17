Bindings
========

Refer to the `Monocypher manual <https://monocypher.org/manual/>`_
for details on the arguments. They should be one-to-one mappings,
and return the expected values, e.g. ``crypto_check``
returns a boolean representing whether the signature is valid,
``crypto_verify16`` returns whether the two byte strings match,
etc.

For parameters which can have unbounded length (except for ``key``
and ``salt``), you can pass in a `bytes-like object <https://docs.python.org/3/glossary.html#term-bytes-like-object>`_.

.. automodule:: monocypher.bindings
   :members:
   :undoc-members:
