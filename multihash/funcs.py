# py-multihash: Python implementation of the multihash specification

"""Enumeration of standard multihash functions, and function registry"""

import hashlib
from collections import namedtuple
from enum import IntEnum
from numbers import Integral
from typing import ClassVar

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

    identity = HASH_CODES["id"]
    sha1 = HASH_CODES["sha1"]
    sha2_256 = HASH_CODES["sha2-256"]
    sha2_512 = HASH_CODES["sha2-512"]
    sha3_512 = HASH_CODES["sha3-512"]
    sha3_384 = HASH_CODES["sha3-384"]
    sha3_256 = HASH_CODES["sha3-256"]
    sha3_224 = HASH_CODES["sha3-224"]
    shake_128 = HASH_CODES["shake-128"]
    shake_256 = HASH_CODES["shake-256"]
    keccak_224 = HASH_CODES["keccak-224"]
    keccak_256 = HASH_CODES["keccak-256"]
    keccak_384 = HASH_CODES["keccak-384"]
    keccak_512 = HASH_CODES["keccak-512"]
    blake2b_256 = HASH_CODES["blake2b-256"]
    blake2b_512 = HASH_CODES["blake2b-512"]
    blake2s_256 = HASH_CODES["blake2s-256"]
    md5 = HASH_CODES.get("md5", 0xD5)  # md5 may not be in constants


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


class FuncReg(metaclass=_FuncRegMeta):
    """Registry of supported hash functions."""

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
        (Func.shake_128, "shake_128", None),  # Variable length
        (Func.shake_256, "shake_256", None),  # Variable length
        (Func.blake2b_256, "blake2b", lambda: hashlib.blake2b(digest_size=32)),
        (Func.blake2b_512, "blake2b", lambda: hashlib.blake2b(digest_size=64)),
        (Func.blake2s_256, "blake2s", lambda: hashlib.blake2s(digest_size=32)),
        (Func.md5, "md5", hashlib.md5),
    ]

    @classmethod
    def reset(cls) -> None:
        """Reset the registry to the standard multihash functions."""
        cls._func_from_name = {}
        cls._func_from_hash = {}
        cls._func_hash = {}

        for func, hash_name, hash_new in cls._std_func_data:
            cls._do_register(func, func.name, hash_name, hash_new)

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
        """Add hash function data to the registry without checks."""
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
        """Return the multihash Func for a hashlib-compatible hash object."""
        return cls._func_from_hash[hash_obj.name]

    @classmethod
    def hash_from_func(cls, func: Func | int):
        """Return a hashlib-compatible object for the multihash func."""
        new = cls._func_hash[func].new
        return new() if new else None


# Initialize the function hash registry.
FuncReg.reset()
