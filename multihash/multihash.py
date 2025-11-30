from binascii import hexlify
from collections import namedtuple
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


class Multihash(namedtuple("Multihash", "code,name,length,digest")):
    """A named tuple representing a multihash function and digest.

    This extends the base namedtuple with additional methods for encoding,
    verification, and compatibility with both py-multihash and pymultihash APIs.
    """

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
                import base64

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

        Args:
            data: The data to verify

        Returns:
            bool: True if the data matches the digest
        """
        # Use the stored length for verification to match the original digest
        computed = _do_digest(data, self.func, length=self.length)
        return computed == self.digest

    def __str__(self):
        """Return a compact string representation of the multihash."""
        import base64

        func_name = self.name if isinstance(self.name, str) else hex(self.code)
        return f"Multihash({func_name}, b64:{base64.b64encode(self.digest).decode()})"


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
        if length is None or length == -1:
            # Default length for SHAKE-128 is 32, SHAKE-256 is 64
            shake_length = 32 if func == Func.shake_128 else 64
        else:
            shake_length = length
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

    This is similar to digest() but follows Go's multihash.Sum() API convention
    where length=-1 means full digest.

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


def sum_stream(stream: BinaryIO, code: Func | str | int, length: int | None = None) -> Multihash:
    """Compute multihash from a stream/file-like object.

    This function reads data from a file-like object in chunks and computes
    the multihash incrementally for memory efficiency.

    Args:
        stream: File-like object with read() method (e.g., file handle, BytesIO)
        code: Hash function code/name (Func enum, str, or int)
        length: Optional truncation length (-1 for full digest, None for auto)

    Returns:
        Multihash: A new Multihash instance with the computed digest

    Raises:
        HashComputationError: If hash computation fails
        TruncationError: If truncation length is invalid

    Example:
        >>> with open("large_file.bin", "rb") as f:
        ...     mh = sum_stream(f, "sha2-256")
        >>> from io import BytesIO
        ...     data = BytesIO(b"streaming data")
        ...     mh = sum_stream(data, Func.sha2_256)
    """
    func = FuncReg.get(code)
    is_shake = func in (Func.shake_128, Func.shake_256)

    # Handle SHAKE functions which require length
    if is_shake:
        if length is None or length == -1:
            # Default length for SHAKE-128 is 32, SHAKE-256 is 64
            shake_length = 32 if func == Func.shake_128 else 64
        else:
            shake_length = length
        hash_obj = FuncReg.hash_from_func(func, length=shake_length)
    else:
        hash_obj = FuncReg.hash_from_func(func)

    if not hash_obj:
        raise HashComputationError(f"no available hash function for {func}")

    # Read in chunks for memory efficiency
    chunk_size = 8192
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
