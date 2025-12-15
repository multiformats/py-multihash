=====
Usage
=====

Basic Usage
===========

To use py-multihash in a project::

    import hashlib
    import multihash

    # hash your data
    m = hashlib.sha256()
    m.update(b'hello world')
    raw_digest = m.digest()

    # add multihash header
    multihash_digest = multihash.encode(raw_digest, "sha2-256")

    # encode it to a string
    multihashed_str = multihash.to_b58_string(multihash_digest)

    print(multihashed_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4

To see that your data follows the header::

    print('  ', m.hexdigest())
    print(multihash.to_hex_string(multihash_digest))

    #     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    # 1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

Hash Computation
================

You can compute hashes directly using the ``digest()`` or ``sum()`` functions::

    from multihash import digest, sum, Func

    # Using digest() function
    mh = digest(b"hello world", Func.sha2_256)
    print(mh.code)  # 0x12
    print(mh.digest.hex())  # Digest in hex

    # Using sum() function (Go-compatible API)
    mh = sum(b"hello world", "sha2-256")
    print(mh.encode('hex'))

Truncation Support
==================

You can truncate digests to a specific length::

    from multihash import sum, Func

    # Truncate to 16 bytes
    mh = sum(b"hello", Func.sha2_256, length=16)
    assert len(mh.digest) == 16

    # Full digest (explicit)
    mh_full = sum(b"hello", Func.sha2_256, length=-1)
    assert len(mh_full.digest) == 32  # Full SHA-256 digest

Streaming Hash Computation
===========================

For large files or streams, use ``sum_stream()``::

    from multihash import sum_stream, Func
    from io import BytesIO

    # From a file
    with open("large_file.bin", "rb") as f:
        mh = sum_stream(f, Func.sha2_256)

    # From BytesIO
    data = BytesIO(b"streaming data")
    mh = sum_stream(data, "sha2-256")

    # With truncation
    with open("file.bin", "rb") as f:
        mh = sum_stream(f, Func.sha2_256, length=16)

SHAKE Variable-Length Hashes
=============================

SHAKE-128 and SHAKE-256 support variable output lengths::

    from multihash import sum, Func

    # SHAKE-128 with default length (32 bytes)
    mh = sum(b"hello", Func.shake_128)
    assert len(mh.digest) == 32

    # SHAKE-128 with custom length
    mh = sum(b"hello", Func.shake_128, length=48)
    assert len(mh.digest) == 48

    # SHAKE-256 with default length (64 bytes)
    mh = sum(b"hello", Func.shake_256)
    assert len(mh.digest) == 64

Modern Hash Functions
=====================

BLAKE3
------

BLAKE3 is a cryptographic hash function that is much faster than MD5, SHA-1, SHA-2,
and SHA-3, yet is just as secure as the latest standard SHA-3::

    from multihash import digest, sum, Func

    # Using BLAKE3
    mh = digest(b"hello world", "blake3")
    print(mh.digest.hex())

    # Or with Func enum
    mh = sum(b"hello world", Func.blake3)

BLAKE2 Variants
---------------

BLAKE2b and BLAKE2s support configurable digest sizes. BLAKE2b supports 8 to 512 bits,
while BLAKE2s supports 8 to 256 bits::

    from multihash import digest, Func

    # BLAKE2b with 256-bit output
    mh = digest(b"data", "blake2b-256")

    # BLAKE2b with 512-bit output (full)
    mh = digest(b"data", "blake2b-512")

    # BLAKE2s with 128-bit output
    mh = digest(b"data", "blake2s-128")

    # All variants from 8 to 512 bits are supported
    mh = digest(b"data", "blake2b-384")  # 384-bit BLAKE2b

Non-Cryptographic Hash Functions
=================================

MurmurHash3
-----------

MurmurHash3 is a fast, non-cryptographic hash function suitable for hash-based lookups,
bloom filters, and other applications where speed is more important than cryptographic security::

    from multihash import digest, Func

    # MurmurHash3 128-bit
    mh = digest(b"hello world", "murmur3-128")
    print(mh.digest.hex())

    # MurmurHash3 32-bit
    mh = digest(b"hello world", "murmur3-32")

.. warning::
    MurmurHash3 is NOT suitable for cryptographic purposes or security-sensitive applications.
    Use SHA-256, SHA-3, BLAKE2, or BLAKE3 for security-critical hashing.

Specialized Hash Functions
===========================

Double-SHA-256
--------------

Double-SHA-256 (SHA-256 applied twice) is commonly used in Bitcoin and other cryptocurrencies::

    from multihash import digest, Func

    # Double-SHA-256 (used in Bitcoin)
    mh = digest(b"block data", "dbl-sha2-256")
    print(mh.digest.hex())

    # Equivalent to: SHA-256(SHA-256(data))

Security Considerations
========================

.. warning::
    MD5 and MD4 are included for backward compatibility but are cryptographically broken.
    Do not use MD5 or MD4 for security-sensitive applications. Use SHA-256 or stronger
    hash functions (e.g., SHA-512, SHA3-256, BLAKE2b) instead.

Error Handling
==============

Custom exceptions are provided for better error handling::

    from multihash import sum, Func, TruncationError, HashComputationError

    try:
        # This will raise TruncationError
        mh = sum(b"hello", Func.sha2_256, length=100)
    except TruncationError as e:
        print(f"Truncation error: {e}")

Verification
=============

You can verify data against a multihash::

    from multihash import digest, Func

    mh = digest(b"hello", Func.sha2_256)

    # Verify the data
    assert mh.verify(b"hello") is True
    assert mh.verify(b"world") is False

MultihashSet Collection
========================

Manage collections of unique multihash values using ``MultihashSet``::

    from multihash import MultihashSet, sum, Func

    # Create a new set
    mh_set = MultihashSet()

    # Add multihashes (Go-style API)
    mh1 = sum(b"file1", Func.sha2_256)
    mh2 = sum(b"file2", Func.sha2_256)
    mh_set.Add(mh1)
    mh_set.Add(mh2)

    # Or use Python-style API
    mh_set.add(mh1)

    # Check membership
    assert mh_set.Has(mh1) is True  # Go-style
    assert mh1 in mh_set  # Python-style

    # Get all items
    all_hashes = mh_set.All()

    # Remove items
    mh_set.Remove(mh1)  # Raises KeyError if not present
    mh_set.discard(mh2)  # Doesn't raise if not present

    # Set operations
    set1 = MultihashSet([mh1, mh2])
    set2 = MultihashSet([mh2, mh3])
    union = set1.union(set2)
    intersection = set1.intersection(set2)
    difference = set1.difference(set2)

    # Iterate over the set
    for mh in mh_set:
        print(mh)

JSON Serialization
===================

Convert multihash objects to and from JSON format::

    from multihash import sum, Func, from_json

    # Create a multihash
    mh = sum(b"hello world", Func.sha2_256)

    # Serialize to JSON (compact format)
    json_str = mh.to_json()
    # {"code": 18, "length": 32, "digest": "base64:..."}

    # Serialize to JSON (verbose format with name)
    json_str = mh.to_json(verbose=True)
    # {"code": 18, "name": "sha2-256", "length": 32, "digest": "base64:..."}

    # Deserialize from JSON
    mh_restored = from_json(json_str)
    assert mh_restored == mh

    # Works with both compact and verbose formats
    mh1 = from_json('{"code": 18, "length": 32, "digest": "..."}')
    mh2 = from_json('{"code": 18, "name": "sha2-256", "length": 32, "digest": "..."}')
