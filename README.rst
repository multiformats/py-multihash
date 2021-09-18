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
* Python versions: Python 3.4, 3.5, 3.6

Example usage::
    
    import multihash

    # compute multihash digest as bytes
    multihash_bytes = multihash.digest(b'hello world', 'sha2-256')
    print(multihash.to_b58_string(multihash_bytes))
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4

    # compute multihash digest as base58 string
    multihash_str = multihash.b58digest(b'hello world', 'sha2-256')
    print(multihash_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4
