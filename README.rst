============
py-multihash
============


.. image:: https://img.shields.io/pypi/v/py-multihash.svg
        :target: https://pypi.python.org/pypi/py-multihash

.. image:: https://github.com/multiformats/py-multihash/actions/workflows/tox.yml/badge.svg
        :target: https://github.com/multiformats/py-multihash/actions

.. image:: https://codecov.io/gh/multiformats/py-multihash/branch/master/graph/badge.svg
        :target: https://codecov.io/gh/multiformats/py-multihash

.. image:: https://readthedocs.org/projects/multihash/badge/?version=latest
        :target: https://multihash.readthedocs.io/en/latest/?badge=latest
        :alt: Documentation Status



Multihash implementation in Python


* Free software: MIT license
* Documentation: https://multihash.readthedocs.io.
* Python versions: Python 3.10, 3.11, 3.12, 3.13, 3.14

Features
--------

* Support for 125+ hash functions including:

  * **Cryptographic hashes**: SHA-1, SHA-2 (224/256/384/512), SHA-3, BLAKE2b, BLAKE2s, BLAKE3
  * **Variable-length hashes**: SHAKE-128, SHAKE-256
  * **Non-cryptographic hashes**: MurmurHash3 (32-bit and 128-bit)
  * **Specialized hashes**: Double-SHA-256 (Bitcoin), Keccak, and more
  * **BLAKE2 variants**: Full range of digest sizes (8-512 bits for BLAKE2b, 8-256 bits for BLAKE2s)

* Streaming hash computation for large files
* Hash truncation support
* JSON serialization
* MultihashSet collection type
* Go-compatible API (``sum()``, ``digest()``, ``verify()``)

Quick Start
-----------

.. code-block:: python

    from multihash import digest, sum, Func

    # Using modern hash functions
    mh = digest(b"hello world", "blake3")

    # Using MurmurHash3 for fast, non-cryptographic hashing
    mh = digest(b"data", "murmur3-128")

    # Using BLAKE2b with custom digest size
    mh = digest(b"data", "blake2b-256")

    # Go-compatible API
    mh = sum(b"hello world", Func.sha2_256)
    print(mh.encode('hex'))

For more examples and usage, see the documentation.
