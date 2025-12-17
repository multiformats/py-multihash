History
=======

.. towncrier release notes start

py-multihash v3.0.0 (2025-12-17)
--------------------------------

Bugfixes
~~~~~~~~

- Added type annotations for ``Multihash`` namedtuple fields (``code``, ``name``, ``length``, ``digest``) to fix static type checker errors. (`#24 <https://github.com/multiformats/py-multihash/issues/24>`__)


Features
~~~~~~~~

- Added pymultihash-compatible APIs to enable py-libp2p migration from the archived pymultihash package. (`#19 <https://github.com/multiformats/py-multihash/issues/19>`__)
- Added streaming hash computation, truncation support, Go-compatible sum() function, SHAKE variable-length hash support, custom exception hierarchy, and additional hash functions (SHA2-224, SHA2-384) to achieve feature parity with other multihash implementations. Also added MultihashSet collection type and JSON serialization support (to_json/from_json) for Priority 3 features. (`#21 <https://github.com/multiformats/py-multihash/issues/21>`__)
- Added BLAKE3, MurmurHash3 (32-bit and 128-bit), and double-SHA-256 hash functions. (`#26 <https://github.com/multiformats/py-multihash/issues/26>`__)
- Add stream I/O methods ``Multihash.read()`` and ``Multihash.write()`` for reading and writing multihashes from/to binary streams. (`#30 <https://github.com/multiformats/py-multihash/issues/30>`__)


Internal Changes - for py-multihash Contributors
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Modernized project setup and infrastructure. Migrated from legacy setup.py/setup.cfg to modern pyproject.toml, replaced Travis CI with GitHub Actions, updated Python version support to 3.10-3.14, replaced flake8 with ruff, and added pre-commit hooks. This is an internal change that does not affect the public API. (`#17 <https://github.com/multiformats/py-multihash/issues/17>`__)


Miscellaneous Changes
~~~~~~~~~~~~~~~~~~~~~

- `#18 <https://github.com/multiformats/py-multihash/issues/18>`__


0.2.3 (2018-10-20)
------------------
* Fix issue with decoding breaking with app codes
* Fix issue with invalid varint decoding

0.1.0 (2018-10-19)
------------------

* First release on PyPI.
