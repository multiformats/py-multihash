=====
Usage
=====

To use `py-multihash` in a project::

    import hashlib
    import multihash

    # hash your data
    m = hashlib.sha256()
    m.update(b'hello world')
    raw_digest = m.digest()

    # add multihash header
    multihash_bytes = multihash.encode(raw_digest, 'sha2-256')

    # encode it to a string
    multihash_str = multihash.to_b58_string(multihash_digest)

    print(multihash_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4

To see that your data follows the header::

    print('  ', m.hexdigest())
    print(multihash.to_hex_string(multihash_digest))

    #     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    # 1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

The multihash digest can also be computed directly::
    
    import multihash

    # compute multihash digest as bytes
    multihash_bytes = multihash.digest(b'hello world', 'sha2-256')
    print(multihash.to_b58_string(multihash_bytes))
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4

    # compute multihash digest as base58 string
    multihash_str = multihash.b58digest(b'hello world', 'sha2-256')
    print(multihash_str)
    # QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4
