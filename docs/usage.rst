=====
Usage
=====

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
