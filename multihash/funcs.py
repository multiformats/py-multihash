# py-multihash: Python implementation of the multihash specification

"""Enumeration of standard multihash functions, and function registry.

This module provides:
- Func: IntEnum of supported hash functions
- FuncReg: Registry for managing hash function implementations
- IdentityHash: hashlib-compatible identity hash
- ShakeHash: Wrapper for variable-length SHAKE hashes

The FuncReg class maintains a registry of hash functions that can be:
- Retrieved by code, name, or hashlib object
- Extended with custom app-specific functions (codes 0x01-0x0F)
- Used to create hashlib-compatible hash objects

Standard functions are pre-registered. App-specific functions can be
registered/unregistered at runtime.
"""

import hashlib
from collections import namedtuple
from enum import IntEnum
from numbers import Integral
from typing import ClassVar

import blake3
import mmh3

from .constants import HASH_CODES


def _is_app_specific_func(code: int) -> bool:
    """Is the given hash function integer `code` application-specific?"""
    return isinstance(code, Integral) and (0x01 <= code <= 0x0F)


class Func(IntEnum):
    """An enumeration of hash functions supported by multihash.

    The name of each member has its hyphens replaced by underscores.
    The value of each member corresponds to its integer code.

    >>> Func.sha2_512.value == 0x13
    True
    """

    # Blake2 variants (sorted alphabetically)
    blake2b_8 = HASH_CODES["blake2b-8"]  # 0xB201
    blake2b_16 = HASH_CODES["blake2b-16"]  # 0xB202
    blake2b_24 = HASH_CODES["blake2b-24"]  # 0xB203
    blake2b_32 = HASH_CODES["blake2b-32"]  # 0xB204
    blake2b_40 = HASH_CODES["blake2b-40"]  # 0xB205
    blake2b_48 = HASH_CODES["blake2b-48"]  # 0xB206
    blake2b_56 = HASH_CODES["blake2b-56"]  # 0xB207
    blake2b_64 = HASH_CODES["blake2b-64"]  # 0xB208
    blake2b_72 = HASH_CODES["blake2b-72"]  # 0xB209
    blake2b_80 = HASH_CODES["blake2b-80"]  # 0xB20A
    blake2b_88 = HASH_CODES["blake2b-88"]  # 0xB20B
    blake2b_96 = HASH_CODES["blake2b-96"]  # 0xB20C
    blake2b_104 = HASH_CODES["blake2b-104"]  # 0xB20D
    blake2b_112 = HASH_CODES["blake2b-112"]  # 0xB20E
    blake2b_120 = HASH_CODES["blake2b-120"]  # 0xB20F
    blake2b_128 = HASH_CODES["blake2b-128"]  # 0xB210
    blake2b_136 = HASH_CODES["blake2b-136"]  # 0xB211
    blake2b_144 = HASH_CODES["blake2b-144"]  # 0xB212
    blake2b_152 = HASH_CODES["blake2b-152"]  # 0xB213
    blake2b_160 = HASH_CODES["blake2b-160"]  # 0xB214
    blake2b_168 = HASH_CODES["blake2b-168"]  # 0xB215
    blake2b_176 = HASH_CODES["blake2b-176"]  # 0xB216
    blake2b_184 = HASH_CODES["blake2b-184"]  # 0xB217
    blake2b_192 = HASH_CODES["blake2b-192"]  # 0xB218
    blake2b_200 = HASH_CODES["blake2b-200"]  # 0xB219
    blake2b_208 = HASH_CODES["blake2b-208"]  # 0xB21A
    blake2b_216 = HASH_CODES["blake2b-216"]  # 0xB21B
    blake2b_224 = HASH_CODES["blake2b-224"]  # 0xB21C
    blake2b_232 = HASH_CODES["blake2b-232"]  # 0xB21D
    blake2b_240 = HASH_CODES["blake2b-240"]  # 0xB21E
    blake2b_248 = HASH_CODES["blake2b-248"]  # 0xB21F
    blake2b_256 = HASH_CODES["blake2b-256"]  # 0xB220
    blake2b_264 = HASH_CODES["blake2b-264"]  # 0xB221
    blake2b_272 = HASH_CODES["blake2b-272"]  # 0xB222
    blake2b_280 = HASH_CODES["blake2b-280"]  # 0xB223
    blake2b_288 = HASH_CODES["blake2b-288"]  # 0xB224
    blake2b_296 = HASH_CODES["blake2b-296"]  # 0xB225
    blake2b_304 = HASH_CODES["blake2b-304"]  # 0xB226
    blake2b_312 = HASH_CODES["blake2b-312"]  # 0xB227
    blake2b_320 = HASH_CODES["blake2b-320"]  # 0xB228
    blake2b_328 = HASH_CODES["blake2b-328"]  # 0xB229
    blake2b_336 = HASH_CODES["blake2b-336"]  # 0xB22A
    blake2b_344 = HASH_CODES["blake2b-344"]  # 0xB22B
    blake2b_352 = HASH_CODES["blake2b-352"]  # 0xB22C
    blake2b_360 = HASH_CODES["blake2b-360"]  # 0xB22D
    blake2b_368 = HASH_CODES["blake2b-368"]  # 0xB22E
    blake2b_376 = HASH_CODES["blake2b-376"]  # 0xB22F
    blake2b_384 = HASH_CODES["blake2b-384"]  # 0xB230
    blake2b_392 = HASH_CODES["blake2b-392"]  # 0xB231
    blake2b_400 = HASH_CODES["blake2b-400"]  # 0xB232
    blake2b_408 = HASH_CODES["blake2b-408"]  # 0xB233
    blake2b_416 = HASH_CODES["blake2b-416"]  # 0xB234
    blake2b_424 = HASH_CODES["blake2b-424"]  # 0xB235
    blake2b_432 = HASH_CODES["blake2b-432"]  # 0xB236
    blake2b_440 = HASH_CODES["blake2b-440"]  # 0xB237
    blake2b_448 = HASH_CODES["blake2b-448"]  # 0xB238
    blake2b_456 = HASH_CODES["blake2b-456"]  # 0xB239
    blake2b_464 = HASH_CODES["blake2b-464"]  # 0xB23A
    blake2b_472 = HASH_CODES["blake2b-472"]  # 0xB23B
    blake2b_480 = HASH_CODES["blake2b-480"]  # 0xB23C
    blake2b_488 = HASH_CODES["blake2b-488"]  # 0xB23D
    blake2b_496 = HASH_CODES["blake2b-496"]  # 0xB23E
    blake2b_504 = HASH_CODES["blake2b-504"]  # 0xB23F
    blake2b_512 = HASH_CODES["blake2b-512"]  # 0xB240
    blake2s_8 = HASH_CODES["blake2s-8"]  # 0xB241
    blake2s_16 = HASH_CODES["blake2s-16"]  # 0xB242
    blake2s_24 = HASH_CODES["blake2s-24"]  # 0xB243
    blake2s_32 = HASH_CODES["blake2s-32"]  # 0xB244
    blake2s_40 = HASH_CODES["blake2s-40"]  # 0xB245
    blake2s_48 = HASH_CODES["blake2s-48"]  # 0xB246
    blake2s_56 = HASH_CODES["blake2s-56"]  # 0xB247
    blake2s_64 = HASH_CODES["blake2s-64"]  # 0xB248
    blake2s_72 = HASH_CODES["blake2s-72"]  # 0xB249
    blake2s_80 = HASH_CODES["blake2s-80"]  # 0xB24A
    blake2s_88 = HASH_CODES["blake2s-88"]  # 0xB24B
    blake2s_96 = HASH_CODES["blake2s-96"]  # 0xB24C
    blake2s_104 = HASH_CODES["blake2s-104"]  # 0xB24D
    blake2s_112 = HASH_CODES["blake2s-112"]  # 0xB24E
    blake2s_120 = HASH_CODES["blake2s-120"]  # 0xB24F
    blake2s_128 = HASH_CODES["blake2s-128"]  # 0xB250
    blake2s_136 = HASH_CODES["blake2s-136"]  # 0xB251
    blake2s_144 = HASH_CODES["blake2s-144"]  # 0xB252
    blake2s_152 = HASH_CODES["blake2s-152"]  # 0xB253
    blake2s_160 = HASH_CODES["blake2s-160"]  # 0xB254
    blake2s_168 = HASH_CODES["blake2s-168"]  # 0xB255
    blake2s_176 = HASH_CODES["blake2s-176"]  # 0xB256
    blake2s_184 = HASH_CODES["blake2s-184"]  # 0xB257
    blake2s_192 = HASH_CODES["blake2s-192"]  # 0xB258
    blake2s_200 = HASH_CODES["blake2s-200"]  # 0xB259
    blake2s_208 = HASH_CODES["blake2s-208"]  # 0xB25A
    blake2s_216 = HASH_CODES["blake2s-216"]  # 0xB25B
    blake2s_224 = HASH_CODES["blake2s-224"]  # 0xB25C
    blake2s_232 = HASH_CODES["blake2s-232"]  # 0xB25D
    blake2s_240 = HASH_CODES["blake2s-240"]  # 0xB25E
    blake2s_248 = HASH_CODES["blake2s-248"]  # 0xB25F
    blake2s_256 = HASH_CODES["blake2s-256"]  # 0xB260
    blake3 = HASH_CODES["blake3"]  # 0x1E
    dbl_sha2_256 = HASH_CODES["dbl-sha2-256"]  # 0x56
    identity = HASH_CODES["id"]  # 0x00
    keccak_224 = HASH_CODES["keccak-224"]  # 0x1A
    keccak_256 = HASH_CODES["keccak-256"]  # 0x1B
    keccak_384 = HASH_CODES["keccak-384"]  # 0x1C
    keccak_512 = HASH_CODES["keccak-512"]  # 0x1D
    md4 = HASH_CODES["md4"]  # 0xD4
    md5 = HASH_CODES["md5"]  # 0xD5
    murmur3_128 = HASH_CODES["murmur3-128"]  # 0x22
    murmur3_32 = HASH_CODES["murmur3-32"]  # 0x23
    ripemd_128 = HASH_CODES["ripemd-128"]  # 0x1052
    ripemd_160 = HASH_CODES["ripemd-160"]  # 0x1053
    ripemd_256 = HASH_CODES["ripemd-256"]  # 0x1054
    ripemd_320 = HASH_CODES["ripemd-320"]  # 0x1055
    sha1 = HASH_CODES["sha1"]  # 0x11
    sha2_224 = HASH_CODES["sha2-224"]  # 0x1013
    sha2_256 = HASH_CODES["sha2-256"]  # 0x12
    sha2_256_trunc254_padded = HASH_CODES["sha2-256-trunc254-padded"]  # 0x1012
    sha2_384 = HASH_CODES["sha2-384"]  # 0x20
    sha2_512 = HASH_CODES["sha2-512"]  # 0x13
    sha2_512_224 = HASH_CODES["sha2-512-224"]  # 0x1014
    sha2_512_256 = HASH_CODES["sha2-512-256"]  # 0x1015
    sha3_224 = HASH_CODES["sha3-224"]  # 0x17
    sha3_256 = HASH_CODES["sha3-256"]  # 0x16
    sha3_384 = HASH_CODES["sha3-384"]  # 0x15
    sha3_512 = HASH_CODES["sha3-512"]  # 0x14
    shake_128 = HASH_CODES["shake-128"]  # 0x18
    shake_256 = HASH_CODES["shake-256"]  # 0x19


class IdentityHash:
    """hashlib-compatible algorithm where the input is the digest."""

    name: str = "identity"

    def __init__(self) -> None:
        self._data = b""

    @property
    def digest_size(self) -> int:
        return len(self._data)

    @property
    def block_size(self) -> int:
        return 1

    def update(self, data: bytes) -> None:
        self._data += data

    def digest(self) -> bytes:
        return self._data

    def hexdigest(self) -> str:
        return self._data.hex()

    def copy(self) -> "IdentityHash":
        c = IdentityHash()
        c._data = self._data
        return c


class _FuncRegMeta(type):
    _func_hash: dict

    def __contains__(cls, func) -> bool:
        """Return whether `func` is a registered function."""
        return func in cls._func_hash

    def __iter__(cls):
        """Iterate over registered functions."""
        return iter(cls._func_hash)


class ShakeHash:
    """Wrapper for SHAKE variable-length hash functions."""

    def __init__(self, shake_func, length: int):
        """Initialize SHAKE hash with specified output length.

        Args:
            shake_func: hashlib.shake_128 or hashlib.shake_256
            length: Output digest length in bytes
        """
        self._shake_func = shake_func
        self._hasher = shake_func()
        self._length = length
        self.name = self._hasher.name

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest of specified length."""
        return self._hasher.digest(self._length)

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "ShakeHash":
        """Create a copy of the hash state."""
        c = ShakeHash(self._shake_func, self._length)
        c._hasher = self._hasher.copy()
        return c


class Blake3Hash:
    """hashlib-compatible wrapper for Blake3 using official blake3 library.

    BLAKE3 is a cryptographic hash function that is much faster than MD5, SHA-1, SHA-2,
    and SHA-3, yet is just as secure as the latest standard SHA-3.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "blake3")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly:
        >>> h = Blake3Hash()
        >>> h.update(b"hello ")
        >>> h.update(b"world")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "blake3"
    digest_size: int = 32
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = blake3.blake3()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest."""
        return self._hasher.digest()

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self._hasher.hexdigest()

    def copy(self) -> "Blake3Hash":
        """Create a copy of the hash state."""
        c = Blake3Hash()
        c._hasher = self._hasher.copy()
        return c


class Murmur3_128Hash:
    """hashlib-compatible wrapper for MurmurHash3 128-bit using official mmh3 library.

    MurmurHash3 is a fast, non-cryptographic hash function suitable for hash-based lookups.
    Note: Not suitable for cryptographic purposes.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "murmur3-128")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly with a custom seed:
        >>> h = Murmur3_128Hash(seed=42)
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "murmur3-128"
    digest_size: int = 16
    block_size: int = 1

    def __init__(self, seed: int = 0) -> None:
        self._data = b""
        self._seed = seed

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._data += data

    def digest(self) -> bytes:
        """Return 128-bit digest."""
        # mmh3.hash128 returns a 128-bit integer
        hash_value = mmh3.hash128(self._data, seed=self._seed, signed=False)
        return hash_value.to_bytes(16, byteorder="little")

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "Murmur3_128Hash":
        """Create a copy of the hash state."""
        c = Murmur3_128Hash(seed=self._seed)
        c._data = self._data
        return c


class Murmur3_32Hash:
    """hashlib-compatible wrapper for MurmurHash3 32-bit using official mmh3 library.

    MurmurHash3 32-bit variant is a fast, non-cryptographic hash function.
    Note: Not suitable for cryptographic purposes.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "murmur3-32")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly with a custom seed:
        >>> h = Murmur3_32Hash(seed=0)
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "murmur3-32"
    digest_size: int = 4
    block_size: int = 1

    def __init__(self, seed: int = 0) -> None:
        self._data = b""
        self._seed = seed

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._data += data

    def digest(self) -> bytes:
        """Return 32-bit digest."""
        # mmh3.hash returns a 32-bit integer
        hash_value = mmh3.hash(self._data, seed=self._seed, signed=False)
        return hash_value.to_bytes(4, byteorder="little")

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "Murmur3_32Hash":
        """Create a copy of the hash state."""
        c = Murmur3_32Hash(seed=self._seed)
        c._data = self._data
        return c


class DoubleSHA256Hash:
    """hashlib-compatible wrapper for double SHA2-256 (used in Bitcoin).

    Applies SHA-256 twice: SHA-256(SHA-256(data)). This is commonly used in Bitcoin
    and other cryptocurrencies for additional security.

    Example:
        >>> from multihash import digest
        >>> mh = digest(b"hello world", "dbl-sha2-256")
        >>> mh.digest.hex()  # doctest: +ELLIPSIS
        '...'
        >>> # Or use the hash class directly:
        >>> h = DoubleSHA256Hash()
        >>> h.update(b"data")
        >>> h.hexdigest()  # doctest: +ELLIPSIS
        '...'
    """

    name: str = "dbl-sha2-256"
    digest_size: int = 32
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest (double SHA-256)."""
        first_hash = self._hasher.digest()
        return hashlib.sha256(first_hash).digest()

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "DoubleSHA256Hash":
        """Create a copy of the hash state."""
        c = DoubleSHA256Hash()
        c._hasher = self._hasher.copy()
        return c


class SHA2_256_Trunc254_Padded_Hash:
    """hashlib-compatible wrapper for SHA2-256 truncated to 254 bits and padded."""

    name: str = "sha2-256-trunc254-padded"
    digest_size: int = 31  # 254 bits = 31.75 bytes, but we use 31 bytes
    block_size: int = 64

    def __init__(self) -> None:
        self._hasher = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Update the hash with data."""
        self._hasher.update(data)

    def digest(self) -> bytes:
        """Return digest (SHA-256 truncated to 254 bits = 31 bytes)."""
        full_hash = self._hasher.digest()
        # Truncate to 254 bits (31 bytes) by taking first 31 bytes
        return full_hash[:31]

    def hexdigest(self) -> str:
        """Return hex digest."""
        return self.digest().hex()

    def copy(self) -> "SHA2_256_Trunc254_Padded_Hash":
        """Create a copy of the hash state."""
        c = SHA2_256_Trunc254_Padded_Hash()
        c._hasher = self._hasher.copy()
        return c


def _create_blake2_variant(variant: str, digest_bytes: int):
    """Factory function to create Blake2 variant classes.

    Args:
        variant: Either 'blake2b' or 'blake2s'
        digest_bytes: Number of bytes in the digest (1-64 for blake2b, 1-32 for blake2s)

    Returns:
        A hashlib-compatible hash class for the specified Blake2 variant

    Example:
        >>> from multihash import digest
        >>> # Use BLAKE2b with 256-bit output
        >>> mh = digest(b"hello", "blake2b-256")
        >>>
        >>> # Use BLAKE2s with 128-bit output
        >>> mh = digest(b"hello", "blake2s-128")
        >>>
        >>> # All variants from 8 to 512 bits (blake2b) or 8 to 256 bits (blake2s) are supported
        >>> mh = digest(b"data", "blake2b-384")
    """

    class Blake2Variant:
        name: str = f"{variant}-{digest_bytes * 8}"
        digest_size: int = digest_bytes
        block_size: int = 128 if variant == "blake2b" else 64

        def __init__(self) -> None:
            hash_func = getattr(hashlib, variant)
            self._hasher = hash_func(digest_size=digest_bytes)

        def update(self, data: bytes) -> None:
            """Update the hash with data."""
            self._hasher.update(data)

        def digest(self) -> bytes:
            """Return digest."""
            return self._hasher.digest()

        def hexdigest(self) -> str:
            """Return hex digest."""
            return self._hasher.hexdigest()

        def copy(self) -> "Blake2Variant":
            """Create a copy of the hash state."""
            c = Blake2Variant()
            c._hasher = self._hasher.copy()
            return c

    return Blake2Variant


class FuncReg(metaclass=_FuncRegMeta):
    """Registry of supported hash functions.

    The FuncReg class maintains a registry of hash functions that can be:
    - Retrieved by code, name, or hashlib object
    - Extended with custom app-specific functions (codes 0x01-0x0F)
    - Used to create hashlib-compatible hash objects

    Standard functions are pre-registered. App-specific functions can be
    registered/unregistered at runtime.

    Example:
        Register an app-specific hash function:
        >>> FuncReg.register(0x05, "my-custom-hash", "myhash", lambda: MyHash())
        >>> func = FuncReg.get("my-custom-hash")
        >>> hash_obj = FuncReg.hash_from_func(func)

        Unregister an app-specific function:
        >>> FuncReg.unregister(0x05)
    """

    _hash = namedtuple("_hash", "name new")

    # Class-level registry attributes
    _func_from_name: ClassVar[dict] = {}
    _func_from_hash: ClassVar[dict] = {}
    _func_hash: ClassVar[dict] = {}

    # Standard hash function data: (func, hashlib_name, constructor)
    _std_func_data: ClassVar[list] = [
        (Func.identity, "identity", IdentityHash),
        (Func.sha1, "sha1", hashlib.sha1),
        (Func.sha2_256, "sha256", hashlib.sha256),
        (Func.sha2_512, "sha512", hashlib.sha512),
        (Func.sha3_512, "sha3_512", hashlib.sha3_512),
        (Func.sha3_384, "sha3_384", hashlib.sha3_384),
        (Func.sha3_256, "sha3_256", hashlib.sha3_256),
        (Func.sha3_224, "sha3_224", hashlib.sha3_224),
        (Func.shake_128, "shake_128", None),  # Variable length - use ShakeHash wrapper
        (Func.shake_256, "shake_256", None),  # Variable length - use ShakeHash wrapper
        (Func.blake2b_256, "blake2b", lambda: hashlib.blake2b(digest_size=32)),
        (Func.blake2b_512, "blake2b", lambda: hashlib.blake2b(digest_size=64)),
        (Func.blake2s_256, "blake2s", lambda: hashlib.blake2s(digest_size=32)),
        (Func.md5, "md5", hashlib.md5),
    ]

    # Additional hash functions (conditionally added if available)
    _optional_func_data: ClassVar[list] = [
        # SHA2 variants (if available in hashlib)
        (Func.sha2_224, "sha224", hashlib.sha224 if hasattr(hashlib, "sha224") else None),
        (Func.sha2_384, "sha384", hashlib.sha384 if hasattr(hashlib, "sha384") else None),
        # SHA2-512 truncated variants (Python 3.6+)
        (Func.sha2_512_224, "sha512_224", getattr(hashlib, "sha512_224", None)),
        (Func.sha2_512_256, "sha512_256", getattr(hashlib, "sha512_256", None)),
        # Blake3 (using official blake3 library)
        (Func.blake3, "blake3", Blake3Hash),
        # Murmur3 variants (using official mmh3 library)
        (Func.murmur3_128, "murmur3-128", Murmur3_128Hash),
        (Func.murmur3_32, "murmur3-32", Murmur3_32Hash),
        # Double SHA2-256 (always available, uses hashlib)
        (Func.dbl_sha2_256, "dbl-sha2-256", DoubleSHA256Hash),
        # SHA2-256 truncated and padded
        (Func.sha2_256_trunc254_padded, "sha2-256-trunc254-padded", SHA2_256_Trunc254_Padded_Hash),
        # Legacy hash functions - RIPEMD variants
        (Func.ripemd_128, "ripemd128", getattr(hashlib, "ripemd128", None)),
        (Func.ripemd_160, "ripemd160", getattr(hashlib, "ripemd160", None)),
        (Func.ripemd_256, "ripemd256", getattr(hashlib, "ripemd256", None)),
        (Func.ripemd_320, "ripemd320", getattr(hashlib, "ripemd320", None)),
        # MD4 (legacy, weak)
        (Func.md4, "md4", getattr(hashlib, "md4", None)),
    ]

    # Blake2 variants - generated programmatically
    @classmethod
    def _generate_blake2_variants(cls):
        """Generate all Blake2b and Blake2s variant registrations."""
        blake2_variants = []

        # Blake2b variants (8 to 512 bits, in 8-bit increments)
        # Skip 256 and 512 as they're already in std_func_data
        for bits in range(8, 520, 8):
            if bits in (256, 512):  # Skip already defined variants
                continue
            digest_bytes = bits // 8
            func_name = f"blake2b_{bits}"
            if hasattr(Func, func_name):
                func = getattr(Func, func_name)
                hash_name = f"blake2b-{bits}"
                hash_class = _create_blake2_variant("blake2b", digest_bytes)
                blake2_variants.append((func, hash_name, hash_class))

        # Blake2s variants (8 to 256 bits, in 8-bit increments)
        # Skip 256 as it's already in std_func_data
        for bits in range(8, 264, 8):
            if bits == 256:  # Skip already defined variant
                continue
            digest_bytes = bits // 8
            func_name = f"blake2s_{bits}"
            if hasattr(Func, func_name):
                func = getattr(Func, func_name)
                hash_name = f"blake2s-{bits}"
                hash_class = _create_blake2_variant("blake2s", digest_bytes)
                blake2_variants.append((func, hash_name, hash_class))

        return blake2_variants

    @classmethod
    def reset(cls) -> None:
        """Reset the registry to the standard multihash functions."""
        cls._func_from_name = {}
        cls._func_from_hash = {}
        cls._func_hash = {}

        for func, hash_name, hash_new in cls._std_func_data:
            cls._do_register(func, func.name, hash_name, hash_new)

        # Register optional functions if available
        for func, hash_name, hash_new in cls._optional_func_data:
            if hash_new is not None:
                try:
                    # Test that the function is actually available by creating an instance.
                    # We don't use the result, just verify it can be instantiated.
                    # The unused variable is intentional - we only care about the side effect
                    # of successful instantiation, not the hash object itself.
                    _ = hash_new()
                    cls._do_register(func, func.name, hash_name, hash_new)
                except (AttributeError, ValueError, TypeError):
                    # Function not available, skip
                    pass

        # Register Blake2 variants
        for func, hash_name, hash_class in cls._generate_blake2_variants():
            try:
                # Test instantiation
                _ = hash_class()
                cls._do_register(func, func.name, hash_name, hash_class)
            except (AttributeError, ValueError, TypeError):
                # Variant not available, skip
                pass

    @classmethod
    def get(cls, func_hint: Func | str | int) -> Func | int:
        """Return a registered hash function matching the given hint."""
        if isinstance(func_hint, int):
            try:
                return Func(func_hint)
            except ValueError:
                pass
        if isinstance(func_hint, str) and func_hint in cls._func_from_name:
            return cls._func_from_name[func_hint]
        if isinstance(func_hint, int) and func_hint in cls._func_hash:
            return func_hint
        raise KeyError("unknown hash function", func_hint)

    @classmethod
    def _do_register(cls, code: int, name: str, hash_name: str | None = None, hash_new=None) -> None:
        """Add hash function data to the registry without checks.

        This method registers the function name in both hyphen and underscore
        variants (e.g., "sha2-256" and "sha2_256") to provide flexibility
        for users who may use either naming convention.
        """
        cls._func_from_name[name.replace("-", "_")] = code
        cls._func_from_name[name.replace("_", "-")] = code
        if hash_name:
            cls._func_from_hash[hash_name] = code
        cls._func_hash[code] = cls._hash(hash_name, hash_new)

    @classmethod
    def register(cls, code: int, name: str, hash_name: str | None = None, hash_new=None) -> None:
        """Add a function to the registry.

        For standard functions already registered, this updates the hash_new
        if provided. For app-specific functions (0x01-0x0f), replaces existing.
        """
        # Check if this is a standard function
        try:
            Func(code)
            is_std_func = True
        except ValueError:
            is_std_func = False

        # For standard functions, just update hash_new if provided
        if is_std_func and code in cls._func_hash:
            if hash_new is not None:
                old_hash = cls._func_hash[code]
                cls._func_hash[code] = cls._hash(old_hash.name or hash_name, hash_new)
            return

        # Check for name conflicts
        for mapping, nameinmap, errmsg in [
            (cls._func_from_name, name, "function name already registered"),
            (cls._func_from_hash, hash_name, "hashlib name already registered"),
        ]:
            if nameinmap is None:
                continue
            existing = mapping.get(nameinmap, code)
            if existing != code:
                raise ValueError(errmsg, existing)

        # Unregister app-specific if existing
        if code in cls._func_hash and _is_app_specific_func(code):
            cls.unregister(code)

        cls._do_register(code, name, hash_name, hash_new)

    @classmethod
    def unregister(cls, code: int) -> None:
        """Remove an application-specific function from the registry."""
        if not _is_app_specific_func(code):
            raise ValueError("only application-specific functions can be unregistered")

        func_names = {n for n, f in cls._func_from_name.items() if f == code}
        for func_name in func_names:
            del cls._func_from_name[func_name]

        hash_data = cls._func_hash.pop(code)
        if hash_data.name:
            del cls._func_from_hash[hash_data.name]

    @classmethod
    def func_from_hash(cls, hash_obj) -> Func | int:
        """Return the multihash Func for a hashlib-compatible hash object.

        Args:
            hash_obj: Hashlib-compatible hash object

        Returns:
            Func enum or int code

        Raises:
            KeyError: If hash object name is not registered
        """
        try:
            return cls._func_from_hash[hash_obj.name]
        except KeyError:
            raise KeyError(f"unknown hash object name: {hash_obj.name}")

    @classmethod
    def hash_from_func(cls, func: Func | int, length: int | None = None):
        """Return a hashlib-compatible object for the multihash func.

        Args:
            func: Hash function code or Func enum
            length: Optional length for SHAKE hashes. Required for SHAKE. Returns None if None for SHAKE.

        Returns:
            Hash object or None if not available

        Note:
            SHAKE functions (shake_128, shake_256) require a length parameter
            to specify the output digest size. If length is None for SHAKE
            functions, this method returns None.
        """
        new = cls._func_hash[func].new
        if new is None:
            # Handle SHAKE functions with variable length
            if func == Func.shake_128:
                if length is None:
                    return None
                return ShakeHash(hashlib.shake_128, length)
            elif func == Func.shake_256:
                if length is None:
                    return None
                return ShakeHash(hashlib.shake_256, length)
            return None
        return new()


# Initialize the function hash registry.
FuncReg.reset()
