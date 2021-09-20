============
py-multihash
============


.. image:: https://img.shields.io/pypi/v/py-multihash.svg
        :target: https://pypi.python.org/pypi/py-multihash

.. image:: https://img.shields.io/travis/multiformats/py-multihash.svg?branch=master
        :target: https://travis-ci.org/multiformats/py-multihash?branch=master

.. image:: https://codecov.io/gh/multiformats/py-multihash/branch/master/graph/badge.svg
        :target: https://codecov.io/gh/multiformats/py-multihash

.. image:: https://readthedocs.org/projects/multihash/badge/?version=stable
        :target: https://multihash.readthedocs.io/en/stable/?badge=stable
        :alt: Documentation Status



Multihash implementation in Python


* Free software: MIT license
* Documentation: https://multihash.readthedocs.io.
* Python versions: Python 3.6, 3.8, 3.8, 3.9


Example usage for end-to-end hashing::
    
    import multihash

    # 1. compute multihash digest as bytes
    multihash_digest = multihash.digest(b'hello world', 'sha2-256')
    print(multihash_digest.hex())
    # 1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

    # 2. encode multihash bytes to base58 string
    print(multihash.to_b58_string(multihash_digest))
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4

    # 1. compute multihash digest directly as base58 string
    multihash_digest_str = multihash.b58digest(b'hello world', 'sha2-256')
    print(multihash_digest_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4


Example usage with pre-computed hash (e.g. using `hashlib`)::

    import hashlib
    import multihash

    # 1. hash your data
    m = hashlib.sha256()
    m.update(b'hello world')
    raw_digest = m.digest()

    # 2. add multihash header to raw digest bytes, see that your data follows the header:
    multihash_digest = multihash.encode(raw_digest, 'sha2-256')
    print('    '+raw_digest.hex())
    print(multihash_digest.hex())
    #     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    # 1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    # ^^^^ header 0x1220: 0x12 is the 'sha2-256' code, 0x20 is the hash length

    # 4. encode multihash bytes to base58 string
    multihash_digest_str = multihash.to_b58_string(multihash_digest)
    print(multihash_digest_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4
