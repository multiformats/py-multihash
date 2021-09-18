"""
    Core functions for the `multihash` module.
"""
# pylint: disable = redefined-outer-name

# -*- coding: utf-8 -*-

import hashlib
from io import BytesIO
from typing import NamedTuple, Optional, Union

import base58 # type: ignore
import skein # type: ignore
import varint # type: ignore

from multihash import constants


# Multihash = namedtuple('Multihash', 'code,name,length,digest')

class Multihash(NamedTuple):
    """
        Typed named tuple class for multihash.
    """

    code: int
    """ Hash function code. """

    name: Union[int, str]
    """ Hash function name if available, same as `code` otherwise. """

    length: int
    """ Hash length. """

    digest: bytes
    """ Hash digest. """


def to_hex_string(multihash: bytes) -> str:
    """
    Convert the given multihash to a hex encoded string

    :param bytes hash: the multihash to be converted to hex string
    :return: input multihash in str
    :rtype: str
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, bytes):
        raise TypeError('multihash should be bytes, not {}'.format(type(multihash)))

    return multihash.hex()


def from_hex_string(multihash: str) -> bytes:
    """
    Convert the given hex encoded string to a multihash

    :param str multihash: hex multihash encoded string
    :return: input multihash in bytes
    :rtype: bytes
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, str):
        raise TypeError('multihash should be str, not {}'.format(type(multihash)))

    return bytes.fromhex(multihash)


def to_b58_string(multihash: bytes) -> str:
    """
    Convert the given multihash to a base58 encoded string

    :param bytes multihash: multihash to base58 encode
    :return: base58 encoded multihash string
    :rtype: str
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, bytes):
        raise TypeError('multihash should be bytes, not {}'.format(type(multihash)))

    return base58.b58encode(multihash).decode()


def from_b58_string(multihash: str) -> bytes:
    """
    Convert the given base58 encoded string to a multihash

    :param str multihash: base58 encoded multihash string
    :return: decoded multihash
    :rtype: bytes
    :raises: `TypeError`, if the `multihash` has incorrect type
    """
    if not isinstance(multihash, str):
        raise TypeError('multihash should be str, not {}'.format(type(multihash)))

    return base58.b58decode(multihash)


def is_app_code(code: int) -> bool:
    """
    Checks whether a code is part of the app range

    :param int code: input code
    :return: if `code` is in the app range or not
    :rtype: bool
    """
    return 0 < code < 0x10


def coerce_code(hash_fn: Union[int, str]) -> int:
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
    :raises TypeError: if the hash type is not a string or an int
    """
    if isinstance(hash_fn, str):
        try:
            return constants.HASH_CODES[hash_fn]
        except KeyError as e:
            raise ValueError('Unsupported hash function {}'.format(hash_fn)) from e

    elif isinstance(hash_fn, int):
        if hash_fn in constants.CODE_HASHES or is_app_code(hash_fn):
            return hash_fn
        raise ValueError('Unsupported hash code {}'.format(hash_fn))

    raise TypeError('hash code should be either an integer or a string')


def is_valid_code(code: int) -> bool:
    """
    Checks whether a multihash code is valid or not

    :param int code: input code
    :return: if the code valid or not
    :rtype: bool
    """
    return is_app_code(code) or code in constants.CODE_HASHES


def decode(multihash: bytes) -> Multihash:
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
        raise TypeError('multihash should be bytes, not {}'.format(type(multihash)))

    if len(multihash) < 3:
        raise ValueError('multihash must be greater than 3 bytes.')

    buffer = BytesIO(multihash)
    try:
        code: int = varint.decode_stream(buffer)
    except TypeError as e:
        raise ValueError('Invalid varint provided') from e

    if not is_valid_code(code):
        raise ValueError('Unsupported hash code {}'.format(code))

    try:
        length: int = varint.decode_stream(buffer)
    except TypeError as e:
        raise ValueError('Invalid length provided') from e

    digest = buffer.read()

    if len(digest) != length:
        raise ValueError('Inconsistent multihash length {} != {}'.format(len(digest), length))

    return Multihash(code=code,
                     name=constants.CODE_HASHES.get(code, code),
                     length=length,
                     digest=digest)


def encode(digest: bytes, hash_fn: Union[int, str], length: Optional[int] = None) -> bytes:
    """
    Encode a hash digest along with the specified function code

    :param bytes digest: hash digest
    :param (int or str) hash_fn: hash function code or name
    :param int length: hash digest length
    :return: encoded multihash
    :rtype: bytes
    :raises TypeError: when the digest is not a bytes object
    :raises ValueError: when the digest length is not correct
    """
    hash_code = coerce_code(hash_fn)

    if not isinstance(digest, bytes):
        raise TypeError('digest must be a bytes object, not {}'.format(type(digest)))

    if length is None:
        length = len(digest)

    elif length != len(digest):
        raise ValueError('digest length should be equal to specified length')

    return varint.encode(hash_code) + varint.encode(length) + digest


def is_valid(multihash: bytes) -> bool:
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


def get_prefix(multihash: bytes) -> bytes:
    """
    Return the prefix from the multihash

    :param bytes multihash: input multihash
    :return: multihash prefix
    :rtype: bytes
    :raises ValueError: when the multihash is invalid
    """
    if is_valid(multihash):
        return multihash[:2]

    raise ValueError('invalid multihash')


def digest(data: bytes, hash_fn: Union[int, str]) -> bytes:
    """
    End-to-end multi-hashing of given `data`, using given hash function (by name or code).
    Returns the multihash as bytes.

    :param hash_fn: The input hash function can be
        - str, the name of the hash function
        - int, the code of the hash function
    :param bytes data: data to be hashed
    :return: multihash of the given data using the given hash function
    :rtype: bytes
    :raises TypeError: when `data` is not a bytes object
    :raises ValueError: if the hash function is not supported
    :raises ValueError: if the hash code is not supported
    :raises TypeError: if the hash type is not a string or an int
    :raises ValueError: if the hash code is an app code
    """
    if not isinstance(data, bytes):
        raise TypeError('data should be bytes, not {}'.format(type(data)))
    code = coerce_code(hash_fn)
    digest: Optional[bytes] = None
    if code in constants.CODE_HASHES:
        length = constants.HASH_LENGTHS[code]
        name = constants.CODE_HASHES[code]
        if name == 'id':
            digest = data
        if digest is None:
            digest = _digest_hashlib(name, data, length)
        if digest is None:
            digest = _digest_skein(name, data, length)
    if digest is None:
        hash_label = hash_fn if isinstance(hash_fn, str) else hex(hash_fn)
        raise ValueError('Unsupported end-to-end hashing for hash function {}'.format(hash_label))
    return encode(digest, hash_fn, length=length)

def b58digest(data: bytes, hash_fn: Union[int, str]) -> str:
    """
    End-to-end multi-hashing of given `data`, using given hash function (by name or code).
    Returns the multihash as a based58-encoded string.

    :param hash_fn: The input hash function can be
        - str, the name of the hash function
        - int, the code of the hash function
    :param bytes data: data to be hashed
    :return: base58-encoded multihash of the given data using the given hash function
    :rtype: str
    :raises TypeError: when `data` is not a bytes object
    :raises ValueError: if the hash function is not supported
    :raises ValueError: if the hash code is not supported
    :raises TypeError: if the hash type is not a string or an int
    :raises ValueError: if the hash code is an app code
    """
    return to_b58_string(digest(data, hash_fn))


def _digest_hashlib(hash_fn: str, data: bytes, length: Optional[int]) -> Optional[bytes]:
    if hash_fn == 'sha1':
        family = 'sha1'
        m = hashlib.sha1()
    else:
        try:
            sep_idx = hash_fn.rindex('-')
        except ValueError:
            return None
        family, reported_len = hash_fn[:sep_idx], hash_fn[sep_idx+1:]
        assert length is not None, 'length must be specified.'
        exp_reported_len = str(length*4 if family == 'shake' else length*8)
        error_msg = 'inconsistent hash length: {} {}.'.format(reported_len, exp_reported_len)
        assert reported_len == exp_reported_len, error_msg
        if family == 'sha2':
            if length not in (0x20, 0x40):
                return None
            m = getattr(hashlib, 'sha{}'.format(length*8))()
        elif family == 'sha3':
            if length not in (0x40, 0x30, 0x20, 0x1c):
                return None
            m = getattr(hashlib, 'sha3_{}'.format(length*8))()
        elif family == 'shake':
            if length not in (0x20, 0x40):
                return None
            m = getattr(hashlib, 'shake_{}'.format(length*4))()
        elif family in ('blake2b', 'blake2s'):
            m = getattr(hashlib, family)(digest_size=length)
        else:
            return None
    m.update(data)
    if family == 'shake':
        digest = m.digest(length)
    else:
        digest = m.digest()
    assert len(digest) == length
    return digest


def _digest_skein(hash_fn: str, data: bytes, length: Optional[int]) -> Optional[bytes]:
    try:
        sep_idx = hash_fn.rindex('-')
    except ValueError:
        return None
    family, reported_len = hash_fn[:sep_idx], hash_fn[sep_idx+1:]
    assert length is not None, 'length must be specified.'
    error_msg = 'inconsistent hash length: {} {}.'.format(int(reported_len), length*8)
    assert int(reported_len) == length*8, error_msg
    if family in ('Skein256', 'Skein512', 'Skein1024'):
        m = getattr(skein, family.lower())(digest_bits=length*8)
    else:
        return None
    m.update(data)
    digest = m.digest()
    assert len(digest) == length
    return digest
