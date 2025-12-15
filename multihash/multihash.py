import base64
import binascii
import json
from binascii import hexlify
from collections import namedtuple
from collections.abc import Iterator
from io import BytesIO
from typing import BinaryIO

import base58
import varint

import multihash.constants as constants
from multihash.exceptions import (
    HashComputationError,
    TruncationError,
)
from multihash.funcs import Func, FuncReg, _is_app_specific_func


def _resolve_shake_length(func: Func | int, length: int | None) -> int:
    """Resolve SHAKE hash output length.

    Args:
        func: SHAKE function (shake_128 or shake_256)
        length: Requested length (None or -1 for default)

    Returns:
        Resolved length in bytes
    """
    if length is None or length == -1:
        # Default length for SHAKE-128 is 32, SHAKE-256 is 64
        return 32 if func == Func.shake_128 else 64
    return length


class Multihash(namedtuple("Multihash", "code,name,length,digest")):
    """A named tuple representing a multihash function and digest.

    This extends the base namedtuple with additional methods for encoding,
    verification, and compatibility with both py-multihash and pymultihash APIs.
    """

    # Type annotations for namedtuple fields (for static type checkers)
    code: int
    name: str
    length: int
    digest: bytes

    __slots__ = ()

    def __new__(cls, code=None, name=None, length=None, digest=None, func=None):
        """Create a new Multihash instance.

        Supports both py-multihash style (code, name, length, digest) and
        pymultihash style (func, digest) constructors.

        Args:
            code: The hash function code (int)
            name: The hash function name (str)
            length: The digest length (int)
            digest: The raw digest bytes
            func: Alternative way to specify the hash function (Func enum, str, or int)
        """
        # Handle pymultihash-style construction: Multihash(func, digest)
        if func is not None or (
            code is not None
            and name is None
            and length is None
            and digest is None
            and isinstance(code, (Func, str, int))
        ):
            # pymultihash style: Multihash(func, digest) or Multihash(code, digest_bytes)
            if func is not None:
                _func = func
                _digest = digest if digest is not None else (name if isinstance(name, bytes) else b"")
            else:
                _func = code
                _digest = name if isinstance(name, bytes) else b""

            # Resolve the function
            try:
                resolved_func = FuncReg.get(_func)
            except KeyError:
                if _is_app_specific_func(_func):
                    resolved_func = int(_func)
                else:
                    raise

            # Get code and name
            if isinstance(resolved_func, Func):
                _code = resolved_func.value
                _name = constants.CODE_HASHES.get(_code, resolved_func.name)
            else:
                _code = resolved_func
                _name = constants.CODE_HASHES.get(_code, _code)

            _length = len(_digest)
            return super().__new__(cls, _code, _name, _length, _digest)

        # Standard py-multihash style construction
        return super().__new__(cls, code, name, length, digest)

    @property
    def func(self):
        """Return the hash function as a Func enum if possible, otherwise the code."""
        try:
            return Func(self.code)
        except ValueError:
            return self.code

    def encode(self, encoding=None):
        """Encode into a multihash-encoded digest.

        Args:
            encoding: Optional encoding name (e.g., 'base64', 'hex', 'base58')

        Returns:
            bytes: The encoded multihash
        """
        mhash = varint.encode(self.code) + varint.encode(self.length) + self.digest

        if encoding:
            if encoding == "base64":
                mhash = base64.b64encode(mhash)
            elif encoding == "hex":
                mhash = hexlify(mhash)
            elif encoding == "base58":
                mhash = base58.b58encode(mhash)
            else:
                raise ValueError(f"Unsupported encoding: {encoding}")

        return mhash

    def verify(self, data):
        """Does the given `data` hash to the digest in this multihash?

        This method uses `self.length` (which may be truncated) for verification
        to ensure it matches the original multihash exactly. For truncated multihashes,
        verification uses the truncated length, not the full digest length.

        Args:
            data: The data to verify

        Returns:
            bool: True if the data matches the digest

        Example:
            >>> mh = sum(b"hello", Func.sha2_256, length=16)  # Truncated to 16 bytes
            >>> mh.verify(b"hello")  # Verifies against 16-byte truncated digest
            True
        """
        # Use the stored length for verification to match the original digest
        computed = _do_digest(data, self.func, length=self.length)
        return computed == self.digest

    def __str__(self):
        """Return a compact string representation of the multihash."""
        func_name = self.name if isinstance(self.name, str) else hex(self.code)
        b64_digest = base64.b64encode(self.digest).decode()
        if len(self.digest) > 64:
            b64_digest = b64_digest[:32] + "..."
        return f"Multihash({func_name}, b64:{b64_digest})"

    def to_json(self, verbose: bool = False) -> str:
        """Convert Multihash to JSON string.

        Args:
            verbose: If True, include 'name' field in output

        Returns:
            JSON string representation

        Raises:
            ValueError: If base64 encoding or JSON serialization fails

        Example:
            >>> mh = sum(b"example", Func.sha2_256)
            >>> mh.to_json()  # doctest: +ELLIPSIS
            '{"code": 18, "length": 32, "digest": "..."}'
            >>> mh.to_json(verbose=True)  # doctest: +ELLIPSIS
            '{"code": 18, "length": 32, "digest": "...", "name": "sha2-256"}'
        """
        try:
            digest_b64 = base64.b64encode(self.digest).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to encode digest to base64: {e}") from e

        data = {
            "code": self.code,
            "length": self.length,
            "digest": digest_b64,
        }
        if verbose:
            data["name"] = self.name if isinstance(self.name, str) else hex(self.code)

        try:
            return json.dumps(data)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to serialize to JSON: {e}") from e

    @classmethod
    def read(cls, stream: BinaryIO) -> "Multihash":
        """Read a multihash from a binary stream.

        This method reads a varint-encoded multihash from a stream, similar to
        the Rust implementation's Multihash::read() method. It reads the code and
        length as varints, then reads the digest bytes.

        Args:
            stream: A binary stream object with read() method (e.g., file handle, BytesIO)

        Returns:
            Multihash: A new Multihash instance read from the stream

        Raises:
            ValueError: If the stream data is invalid or insufficient
            TypeError: If stream is not a valid binary stream

        Example:
            Reading from a BytesIO stream:
            >>> from io import BytesIO
            >>> data = BytesIO(b'\\x12\\x20' + b'0' * 32)  # sha2-256 with 32-byte digest
            >>> mh = Multihash.read(data)

            Reading from a file:
            >>> with open("multihash.bin", "rb") as f:
            ...     mh = Multihash.read(f)

            Reading multiple multihashes from a stream:
            >>> from io import BytesIO
            >>> data = BytesIO(b'\\x12\\x20' + b'0' * 32 + b'\\x12\\x20' + b'1' * 32)
            >>> mh1 = Multihash.read(data)
            >>> mh2 = Multihash.read(data)
        """
        try:
            code = varint.decode_stream(stream)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to read multihash code from stream: {e}") from e

        if not is_valid_code(code):
            raise ValueError(f"Invalid multihash code: {code}")

        try:
            length = varint.decode_stream(stream)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Failed to read multihash length from stream: {e}") from e

        digest = stream.read(length)
        if len(digest) != length:
            raise ValueError(f"Insufficient data in stream: expected {length} bytes, got {len(digest)}")

        name = constants.CODE_HASHES.get(code, code)
        return cls(code=code, name=name, length=length, digest=digest)

    def write(self, stream: BinaryIO) -> int:
        """Write this multihash to a binary stream.

        This method writes the multihash to a stream in varint-encoded format,
        similar to the Rust implementation's Multihash::write() method.

        Args:
            stream: A binary stream object with write() method (e.g., file handle, BytesIO)

        Returns:
            int: The number of bytes written to the stream

        Raises:
            TypeError: If stream is not a valid binary stream
            OSError: If writing to the stream fails

        Example:
            Writing to a BytesIO stream:
            >>> from io import BytesIO
            >>> mh = sum(b"hello", Func.sha2_256)
            >>> stream = BytesIO()
            >>> bytes_written = mh.write(stream)
            >>> stream.getvalue()  # Get the written bytes

            Writing to a file:
            >>> mh = sum(b"hello", Func.sha2_256)
            >>> with open("multihash.bin", "wb") as f:
            ...     bytes_written = mh.write(f)

            Writing multiple multihashes to a stream:
            >>> from io import BytesIO
            >>> mh1 = sum(b"data1", Func.sha2_256)
            >>> mh2 = sum(b"data2", Func.sha2_256)
            >>> stream = BytesIO()
            >>> mh1.write(stream)
            >>> mh2.write(stream)
        """
        try:
            encoded = varint.encode(self.code) + varint.encode(self.length) + self.digest
            bytes_written = stream.write(encoded)
            return bytes_written
        except (AttributeError, TypeError) as e:
            raise TypeError(f"Stream must have a write() method: {e}") from e
        except OSError as e:
            raise OSError(f"Failed to write multihash to stream: {e}") from e


class MultihashSet:
    """A specialized collection for managing unique Multihash values.

    This class provides both Go-compatible API (Add, Remove, Has, All) and
    Pythonic set operations. It ensures type safety by only accepting Multihash
    objects.

    Example:
        >>> mh_set = MultihashSet()
        >>> mh1 = sum(b"file1", Func.sha2_256)
        >>> mh_set.Add(mh1)  # Go-style
        >>> mh2 = sum(b"file2", Func.sha2_256)  # Define mh2
        >>> mh_set.add(mh2)   # Python-style
        >>> mh_set.Has(mh1)   # True
        True
        >>> len(mh_set)       # 2
        2
    """

    def __init__(self, iterable=None):
        """Initialize a new MultihashSet.

        Args:
            iterable: Optional iterable of Multihash objects to initialize the set

        Raises:
            TypeError: If iterable contains non-Multihash objects
        """
        self._set: set[Multihash] = set()
        if iterable is not None:
            for item in iterable:
                if not isinstance(item, Multihash):
                    raise TypeError(f"MultihashSet can only contain Multihash objects, got {type(item)}")
                self._set.add(item)

    def Add(self, mh: Multihash) -> None:
        """Add a Multihash to the set (Go-style API).

        Args:
            mh: Multihash object to add

        Raises:
            TypeError: If mh is not a Multihash object
        """
        if not isinstance(mh, Multihash):
            raise TypeError(f"MultihashSet can only contain Multihash objects, got {type(mh)}")
        self._set.add(mh)

    def add(self, mh: Multihash) -> None:
        """Add a Multihash to the set (Python-style API).

        Args:
            mh: Multihash object to add

        Raises:
            TypeError: If mh is not a Multihash object
        """
        self.Add(mh)

    def Remove(self, mh: Multihash) -> None:
        """Remove a Multihash from the set (Go-style API).

        Args:
            mh: Multihash object to remove

        Raises:
            KeyError: If mh is not in the set
            TypeError: If mh is not a Multihash object
        """
        if not isinstance(mh, Multihash):
            raise TypeError(f"MultihashSet can only contain Multihash objects, got {type(mh)}")
        self._set.remove(mh)

    def remove(self, mh: Multihash) -> None:
        """Remove a Multihash from the set (Python-style API).

        Args:
            mh: Multihash object to remove

        Raises:
            KeyError: If mh is not in the set
            TypeError: If mh is not a Multihash object
        """
        self.Remove(mh)

    def discard(self, mh: Multihash) -> None:
        """Remove a Multihash from the set if present (does not raise KeyError).

        Args:
            mh: Multihash object to remove
        """
        if isinstance(mh, Multihash):
            self._set.discard(mh)

    def Has(self, mh: Multihash) -> bool:
        """Check if a Multihash is in the set (Go-style API).

        Args:
            mh: Multihash object to check

        Returns:
            True if mh is in the set, False otherwise
        """
        return mh in self._set

    def __contains__(self, mh: Multihash) -> bool:
        """Check if a Multihash is in the set (Python-style API).

        Args:
            mh: Multihash object to check

        Returns:
            True if mh is in the set, False otherwise
        """
        return self.Has(mh)

    def All(self) -> list[Multihash]:
        """Return all Multihash objects in the set (Go-style API).

        Returns:
            List of all Multihash objects in the set
        """
        return list(self._set)

    def __len__(self) -> int:
        """Return the number of Multihash objects in the set.

        Returns:
            Number of items in the set
        """
        return len(self._set)

    def __iter__(self) -> Iterator[Multihash]:
        """Return an iterator over the Multihash objects in the set.

        Returns:
            Iterator over Multihash objects
        """
        return iter(self._set)

    def union(self, other: "MultihashSet") -> "MultihashSet":
        """Return a new MultihashSet with elements from both sets.

        Args:
            other: Another MultihashSet to union with

        Returns:
            New MultihashSet containing elements from both sets
        """
        result = MultihashSet(self._set)
        result._set.update(other._set)
        return result

    def intersection(self, other: "MultihashSet") -> "MultihashSet":
        """Return a new MultihashSet with elements common to both sets.

        Args:
            other: Another MultihashSet to intersect with

        Returns:
            New MultihashSet containing common elements
        """
        return MultihashSet(self._set & other._set)

    def difference(self, other: "MultihashSet") -> "MultihashSet":
        """Return a new MultihashSet with elements in this set but not in other.

        Args:
            other: Another MultihashSet to difference with

        Returns:
            New MultihashSet containing elements only in this set
        """
        return MultihashSet(self._set - other._set)

    def symmetric_difference(self, other: "MultihashSet") -> "MultihashSet":
        """Return a new MultihashSet with elements in either set but not both.

        Args:
            other: Another MultihashSet to symmetric difference with

        Returns:
            New MultihashSet containing elements in either set but not both
        """
        return MultihashSet(self._set ^ other._set)

    def clear(self) -> None:
        """Remove all Multihash objects from the set."""
        self._set.clear()

    def __repr__(self) -> str:
        """Return a string representation of the MultihashSet.

        Returns:
            String representation showing the number of items
        """
        return f"MultihashSet({len(self._set)} items)"


def from_json(json_str: str) -> Multihash:
    """Create Multihash from JSON string.

    Args:
        json_str: JSON string representation of Multihash

    Returns:
        Multihash instance

    Raises:
        ValueError: If JSON is invalid or missing required fields
        TypeError: If digest cannot be decoded

    Example:
        >>> mh_test = sum(b"test", Func.sha2_256)
        >>> json_str = mh_test.to_json()
        >>> mh = from_json(json_str)
        >>> mh_test2 = sum(b"test", Func.sha2_256)
        >>> json_str_verbose = mh_test2.to_json(verbose=True)
        >>> mh = from_json(json_str_verbose)
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON string: {e}") from e

    # Validate required fields
    required_fields = ["code", "length", "digest"]
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        raise ValueError(f"Missing required fields: {missing_fields}")

    # Extract and validate fields
    code = data["code"]
    length = data["length"]
    digest_str = data["digest"]

    # Decode base64 digest
    try:
        digest_bytes = base64.b64decode(digest_str)
    except (binascii.Error, ValueError) as e:
        raise TypeError(f"Failed to decode base64 digest: {e}") from e

    # Validate length matches
    if length != len(digest_bytes):
        raise ValueError(f"Length mismatch: expected {length}, got {len(digest_bytes)}")

    # Get name if provided, otherwise resolve from code
    name = data.get("name")
    if name is None:
        # Resolve name from code
        name = constants.CODE_HASHES.get(code, hex(code))

    return Multihash(code=code, name=name, length=length, digest=digest_bytes)


def _do_digest(data, func, length: int | None = None):
    """Return the binary digest of `data` with the given `func`.

    Args:
        data: Input data to hash (bytes)
        func: Hash function code/name
        length: Optional truncation length (-1 means full digest, None means auto)

    Returns:
        bytes: Digest bytes (truncated if length specified)

    Raises:
        HashComputationError: If hash computation fails
        TruncationError: If truncation length is invalid
    """
    func = FuncReg.get(func)
    is_shake = func in (Func.shake_128, Func.shake_256)

    # Handle SHAKE functions which require length
    if is_shake:
        shake_length = _resolve_shake_length(func, length)
        hash_obj = FuncReg.hash_from_func(func, length=shake_length)
    else:
        hash_obj = FuncReg.hash_from_func(func)

    if not hash_obj:
        raise HashComputationError(f"no available hash function for {func}")

    hash_obj.update(data)
    digest_bytes = bytes(hash_obj.digest())

    # Handle truncation (but not for SHAKE, as they already produce the right length)
    if not is_shake and length is not None and length != -1:
        if length < 0:
            raise TruncationError(f"truncation length must be non-negative, got {length}")
        if length == 0:
            raise TruncationError("truncation length cannot be zero")
        if length > len(digest_bytes):
            raise TruncationError(f"truncation length {length} exceeds digest size {len(digest_bytes)}")
        digest_bytes = digest_bytes[:length]

    return digest_bytes


def digest(data, func, length: int | None = None):
    """Hash the given `data` into a new `Multihash`.

    The given hash function `func` is used to perform the hashing.  It must be
    a registered hash function (see `FuncReg`).

    Args:
        data: The data to hash (bytes)
        func: The hash function to use (Func enum, str, or int)
        length: Optional truncation length (-1 for full digest, None for auto)

    Returns:
        Multihash: A new Multihash instance with the computed digest

    Example:
        >>> data = b'foo'
        >>> mh = digest(data, Func.sha1)
        >>> mh.encode('base64')
        b'ERQL7se16j8P28ldDdR/PFvCddqKMw=='
        >>> mh_truncated = digest(data, Func.sha2_256, length=16)
    """
    digest_bytes = _do_digest(data, func, length=length)
    return Multihash(func=func, digest=digest_bytes)


def to_hex_string(multihash):
    """
    Convert the given multihash to a hex encoded string

    :param bytes hash: the multihash to be converted to hex string
    :return: input multihash in str
    :rtype: str
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, bytes):
        raise TypeError(f"multihash should be bytes, not {type(multihash)}")

    return hexlify(multihash).decode()


def from_hex_string(multihash):
    """
    Convert the given hex encoded string to a multihash

    :param str multihash: hex multihash encoded string
    :return: input multihash in bytes
    :rtype: bytes
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, str):
        raise TypeError(f"multihash should be str, not {type(multihash)}")

    return bytes.fromhex(multihash)


def to_b58_string(multihash):
    """
    Convert the given multihash to a base58 encoded string

    :param bytes multihash: multihash to base58 encode
    :return: base58 encoded multihash string
    :rtype: str
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, bytes):
        raise TypeError(f"multihash should be bytes, not {type(multihash)}")

    return base58.b58encode(multihash).decode()


def from_b58_string(multihash):
    """
    Convert the given base58 encoded string to a multihash

    :param str multihash: base58 encoded multihash string
    :return: decoded multihash
    :rtype: bytes
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, str):
        raise TypeError(f"multihash should be str, not {type(multihash)}")

    return base58.b58decode(multihash)


def is_app_code(code):
    """
    Checks whether a code is part of the app range

    :param int code: input code
    :return: if `code` is in the app range or not
    :rtype: bool
    """
    return 0 < code < 0x10


def coerce_code(hash_fn):
    """
    Converts a hash function name into its code

    If passed a number it will return the number if it's a valid code

    :param hash_fn: The input hash function can be
        - str, the name of the hash function
        - int, the code of the hash function
    :return: hash function code
    :rtype: int
    :raises ValueError: if the hash function is not supported
    :raises ValueError: if the hash code is not supported
    :raises ValueError: if the hash type is not a string or an int
    """
    if isinstance(hash_fn, str):
        try:
            return constants.HASH_CODES[hash_fn]
        except KeyError:
            raise ValueError(f"Unsupported hash function {hash_fn}")

    elif isinstance(hash_fn, int):
        if hash_fn in constants.CODE_HASHES or is_app_code(hash_fn):
            return hash_fn
        raise ValueError(f"Unsupported hash code {hash_fn}")

    raise TypeError("hash code should be either an integer or a string")


def is_valid_code(code):
    """
    Checks whether a multihash code is valid or not

    :param int code: input code
    :return: if the code valid or not
    :rtype: bool
    """
    return is_app_code(code) or code in constants.CODE_HASHES


def decode(multihash):
    """
    Decode a hash from the given multihash

    :param bytes multihash: multihash
    :return: decoded :py:class:`multihash.Multihash` object
    :rtype: :py:class:`multihash.Multihash`
    :raises TypeError: if `multihash` is not of type `bytes`
    :raises ValueError: if the length of multihash is less than 3 characters
    :raises ValueError: if the code is invalid
    :raises ValueError: if the length is invalid
    :raises ValueError: if the length is not same as the digest
    """
    if not isinstance(multihash, bytes):
        raise TypeError("multihash should be bytes, not {}", type(multihash))

    if len(multihash) < 3:
        raise ValueError("multihash must be greater than 3 bytes.")

    buffer = BytesIO(multihash)
    try:
        code = varint.decode_stream(buffer)
    except TypeError:
        raise ValueError("Invalid varint provided")

    if not is_valid_code(code):
        raise ValueError(f"Unsupported hash code {code}")

    try:
        length = varint.decode_stream(buffer)
    except TypeError:
        raise ValueError("Invalid length provided")

    buf = buffer.read()

    if len(buf) != length:
        raise ValueError(f"Inconsistent multihash length {len(buf)} != {length}")

    return Multihash(code=code, name=constants.CODE_HASHES.get(code, code), length=length, digest=buf)


def encode(digest, code, length=None):
    """
    Encode a hash digest along with the specified function code

    :param bytes digest: hash digest
    :param (int or str) code: hash function code
    :param int length: hash digest length
    :return: encoded multihash
    :rtype: bytes
    :raises TypeError: when the digest is not a bytes object
    :raises ValueError: when the digest length is not correct
    """
    hash_code = coerce_code(code)

    if not isinstance(digest, bytes):
        raise TypeError(f"digest must be a bytes object, not {type(digest)}")

    if length is None:
        length = len(digest)

    elif length != len(digest):
        raise ValueError("digest length should be equal to specified length")

    return varint.encode(hash_code) + varint.encode(length) + digest


def is_valid(multihash):
    """
    Check if the given buffer is a valid multihash

    :param bytes multihash: input multihash
    :return: if the input is a valid multihash or not
    :rtype: bool
    """
    try:
        decode(multihash)
        return True
    except ValueError:
        return False


def get_prefix(multihash):
    """
    Return the prefix from the multihash

    :param bytes multihash: input multihash
    :return: multihash prefix
    :rtype: bytes
    :raises ValueError: when the multihash is invalid
    """
    if is_valid(multihash):
        return multihash[:2]

    raise ValueError("invalid multihash")


def sum(data: bytes, code: Func | str | int, length: int | None = None) -> Multihash:
    """Compute multihash for data (Go-compatible API).

    This function provides a Go-compatible API for computing multihashes.
    It is a thin wrapper around digest() that follows Go's multihash.Sum()
    convention where length=-1 means full digest.

    Use this function when:
    - Migrating from Go multihash implementations
    - You prefer the Go-style API naming

    Use digest() when:
    - You prefer Pythonic naming conventions
    - You want the more descriptive function name

    Args:
        data: Input data to hash (bytes)
        code: Hash function code/name (Func enum, str, or int)
        length: Truncation length (-1 for full digest, None for auto, or specific length)

    Returns:
        Multihash: A new Multihash instance with the computed digest

    Example:
        >>> mh = sum(b"hello", "sha2-256")
        >>> mh_truncated = sum(b"hello", "sha2-256", length=16)
        >>> mh_full = sum(b"hello", "sha2-256", length=-1)  # Full digest
    """
    return digest(data, code, length=length)


def sum_stream(
    stream: BinaryIO, code: Func | str | int, length: int | None = None, chunk_size: int = 8192
) -> Multihash:
    """Compute multihash from a stream/file-like object.

    This function reads data from a file-like object in chunks and computes
    the multihash incrementally for memory efficiency.

    Args:
        stream: File-like object with read() method (e.g., file handle, BytesIO)
        code: Hash function code/name (Func enum, str, or int)
        length: Optional truncation length (-1 for full digest, None for auto)
        chunk_size: Size of chunks to read from stream (default: 8192 bytes)

    Returns:
        Multihash: A new Multihash instance with the computed digest

    Raises:
        HashComputationError: If hash computation fails
        TruncationError: If truncation length is invalid
        ValueError: If chunk_size is not positive

    Example:
        Using with a file handle:
        >>> with open("large_file.bin", "rb") as f:
        ...     mh = sum_stream(f, "sha2-256")

        Using with BytesIO:
        >>> from io import BytesIO
        >>> data = BytesIO(b"streaming data")
        >>> mh = sum_stream(data, Func.sha2_256)

        Using with truncation:
        >>> with open("file.bin", "rb") as f:
        ...     mh = sum_stream(f, Func.sha2_256, length=16)

        Using with custom chunk size:
        >>> with open("large_file.bin", "rb") as f:
        ...     mh = sum_stream(f, Func.sha2_256, chunk_size=16384)
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")

    func = FuncReg.get(code)
    is_shake = func in (Func.shake_128, Func.shake_256)

    # Handle SHAKE functions which require length
    if is_shake:
        shake_length = _resolve_shake_length(func, length)
        hash_obj = FuncReg.hash_from_func(func, length=shake_length)
    else:
        hash_obj = FuncReg.hash_from_func(func)

    if not hash_obj:
        raise HashComputationError(f"no available hash function for {func}")

    # Read in chunks for memory efficiency
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hash_obj.update(chunk)

    digest_bytes = bytes(hash_obj.digest())

    # Handle truncation (but not for SHAKE, as they already produce the right length)
    if not is_shake and length is not None and length != -1:
        if length < 0:
            raise TruncationError(f"truncation length must be non-negative, got {length}")
        if length == 0:
            raise TruncationError("truncation length cannot be zero")
        if length > len(digest_bytes):
            raise TruncationError(f"truncation length {length} exceeds digest size {len(digest_bytes)}")
        digest_bytes = digest_bytes[:length]

    return Multihash(func=code, digest=digest_bytes)
