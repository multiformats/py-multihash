=====
Usage
=====

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
