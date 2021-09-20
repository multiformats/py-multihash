#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `multihash` package."""
# pylint: disable = missing-function-docstring, missing-class-docstring, no-self-use

from binascii import hexlify
import hashlib

import base58
import pytest
import skein  # type: ignore

from multihash import (
    encode, decode, from_hex_string, to_hex_string, to_b58_string, from_b58_string, is_app_code,
    is_valid, is_valid_code, get_prefix, coerce_code, digest
)
from multihash.constants import HASH_TABLE

VALID_TABLE = (
    {
        'encoding': {
            'code': 0x11,
            'name': 'sha1',
        },
        'hex': '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33',
        'length': 20,
    },
    {
        'encoding': {
            'code': 0x11,
            'name': 'sha1',
        },
        'hex': '0beec7b8',
        'length': 4,
    },
    {
        'encoding': {
            'code': 0x12,
            'name': 'sha2-256',
        },
        'hex': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
        'length': 32,
    },
    {
        'encoding': {
            'code': 0x12,
            'name': 'sha2-256',
        },
        'hex': '2c26b46b',
        'length': 4,
    },
)

INVALID_TABLE = (
    {
        'code': 0x00,
        'length': 32,
        'hex': '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33'
    },
    {
        'code': 0x11,
        'length': 21,
        'hex': '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33'
    },
    {
        'code': 0x11,
        'length': 20,
        'hex': '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a'
    },
    {
        'code': 0x11,
        'length': 20,
        'hex': 'f0'
    },
    {
        'code': 0x31,
        'length': 20,
        'hex': '0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33'
    },
    {
        'code': 0x12,
        'length': 32,
        'hex': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7'
    },
    {
        'code': 0xb205,
        'length': 5,
        'hex': '2c26b0'
    },
    {
        'code': 0xb23f,
        'length': 0x3f,
        'hex': ('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7'
                '2c26b46b6f8ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e')
    },
)

INVALID_BYTE_TYPES: tuple = ('a', 1, 1.0, [], {})
INVALID_STRING_TYPES: tuple = (b'a', 1, 1.0, [], {})


def make_hash(code, size, hex_):
    return code.to_bytes((code.bit_length() + 7) // 8, byteorder='big') + \
        size.to_bytes((size.bit_length() + 7) // 8, byteorder='big') + \
        bytes.fromhex(hex_)


class ToHexStringTestCase:
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_to_hex_string_valid(self, value):
        """ to_hex_string: test if it passes for all valid cases """
        code = value['encoding']['code']
        buffer = encode(bytes.fromhex(value['hex']), code)
        assert to_hex_string(buffer) == hexlify(buffer).decode()

    @pytest.mark.parametrize('value', INVALID_BYTE_TYPES)
    def test_to_hex_string_invalid_type(self, value):
        """ to_hex_string: raises TypeError for invalid types """
        with pytest.raises(TypeError) as excinfo:
            to_hex_string(value)
        assert 'multihash should be bytes' in str(excinfo.value)


class FromHexStringTestCase:
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_from_digest_string_valid(self, value):
        """ from_hex_string: decodes the correct values """
        code = value['encoding']['code']
        buffer = encode(bytes.fromhex(value['hex']), code)
        assert from_hex_string(hexlify(buffer).decode()) == buffer

    @pytest.mark.parametrize('value', INVALID_STRING_TYPES)
    def test_from_hex_string_invalid_type(self, value):
        """ from_hex_string: raises TypeError for invalid types """
        with pytest.raises(TypeError) as excinfo:
            from_hex_string(value)
        assert 'multihash should be str' in str(excinfo.value)


class To58StringTestCase:
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_to_b58_string_valid(self, value):
        """ to_b58_string: test if it passes for all valid cases """
        code = value['encoding']['code']
        buffer = encode(bytes.fromhex(value['hex']), code)
        assert to_b58_string(buffer) == base58.b58encode(buffer).decode()

    @pytest.mark.parametrize('value', INVALID_BYTE_TYPES)
    def test_to_b58_string_invalid(self, value):
        """ to_b58_string: raises TypeError for invalid types """
        with pytest.raises(TypeError) as excinfo:
            to_b58_string(value)
        assert 'multihash should be bytes' in str(excinfo.value)


class FromB58StringTestCase:
    def test_from_b58_string_valid(self):
        """ from_b58_string: test if it passes for all valid cases """
        expected = 'QmPfjpVaf593UQJ9a5ECvdh2x17XuJYG5Yanv5UFnH3jPE'
        actual = bytes.fromhex('122013bf801597d74a660453412635edd8c34271e5998f801fac5d700c6ce8d8e461')
        assert from_b58_string(expected) == actual

    @pytest.mark.parametrize('value', INVALID_STRING_TYPES)
    def test_from_b58_string_invalid(self, value):
        """ from_b58_string: raises TypeError for invalid types """
        with pytest.raises(TypeError) as excinfo:
            from_b58_string(value)
        assert 'multihash should be str' in str(excinfo.value)


class IsAppCodeTestCase:
    @pytest.mark.parametrize('value', (0x01, 0x0f, 0x04))
    def test_is_app_code_valid(self, value):
        """ is_app_code: returns True for all valid cases """
        assert is_app_code(value)

    @pytest.mark.parametrize('value', (0x00, 0x11, 0x10, 0xffff))
    def test_is_app_code_invalid(self, value):
        """ is_app_code: returns False for invalid cases """
        assert not is_app_code(value)


class CoerceCodeTestCase:
    @pytest.mark.parametrize('value', HASH_TABLE[:15] + HASH_TABLE[:15])
    def test_coerce_code_valid(self, value):
        """ coerce_code: returns code for all valid cases """
        assert coerce_code(value['hash']) == value['code']
        assert coerce_code(value['code']) == value['code']

    @pytest.mark.parametrize('value', ('SHa1', 'SHA256', 0xf0f0ff0))
    def test_coerce_code_invalid(self, value):
        """ coerce_code: raises ValueError for invalid cases """
        with pytest.raises(ValueError) as excinfo:
            coerce_code(value)
        assert 'Unsupported hash' in str(excinfo.value)

    @pytest.mark.parametrize('value', (1., [], {}))
    def test_coerce_code_invalid_type(self, value):
        """ coerce_code: raises TypeError for invalid cases """
        with pytest.raises(TypeError) as excinfo:
            coerce_code(value)
        assert 'should be either an integer or a string' in str(excinfo.value)


class IsValidCodeTestCase:
    @pytest.mark.parametrize('value', (0x02, 0x0f, 0x13))
    def test_is_valid_code_valid(self, value):
        """ is_valid_code: returns True for all valid cases """
        assert is_valid_code(value)

    @pytest.mark.parametrize('value', (0x0ff, 0x10, 0x90))
    def test_is_valid_code_invalid(self, value):
        """ is_valid_code: returns False for all invalid cases """
        assert not is_valid_code(value)


class DecodeTestCase:
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_decode_valid(self, value):
        """ decode: works for all valid cases """
        code = value['encoding']['code']
        buffer = make_hash(code, value['length'], value['hex'])
        name = value['encoding']['name']
        actual = bytes.fromhex(value['hex'])

        r = decode(buffer)
        expected = r.digest

        assert r.code == code
        assert r.name == name
        assert r.length == len(actual)
        assert actual == expected

    def test_decode_app_code(self):
        """ decode: works for all app codes """
        code = 0x08
        hex_ = 'fdfdfdfdfd'
        buffer = make_hash(code, 5, hex_)
        actual = bytes.fromhex(hex_)

        r = decode(buffer)
        expected = r.digest

        assert r.code == code
        assert r.length == len(actual)
        assert actual == expected

    @pytest.mark.parametrize('value', INVALID_BYTE_TYPES)
    def test_decode_incorrect_types(self, value):
        """ decode: raises TypeError if the type is incorrect """
        with pytest.raises(TypeError) as excinfo:
            decode(value)
        assert 'should be bytes' in str(excinfo.value)

    @pytest.mark.parametrize('value', (b'', b'a', b'aa'))
    def test_decode_less_length(self, value):
        """ decode: raises ValueError if the length is less than 3 """
        with pytest.raises(ValueError) as excinfo:
            decode(value)
        assert 'greater than 3 bytes' in str(excinfo.value)

    def test_decode_invalid_code(self):
        """ decode: raises ValueError if the code is invalid """
        value = make_hash(0xfff0, 10, 'ffffffff')
        with pytest.raises(ValueError) as excinfo:
            decode(value)
        assert 'Unsupported hash code' in str(excinfo.value)

    def test_decode_invalid_length(self):
        """ decode: raises ValueError if the length is invalid """
        value = make_hash(0x13, 0, 'ffffffff')
        with pytest.raises(ValueError) as excinfo:
            decode(value)
        assert 'Invalid length' in str(excinfo.value)

    def test_decode_unequal_length(self):
        """ decode: raises ValueError if the length is not same """
        value = make_hash(0x13, 40, 'ffffffff')
        with pytest.raises(ValueError) as excinfo:
            decode(value)
        assert 'Inconsistent multihash length' in str(excinfo.value)

    def test_decode_invalid_varint(self):
        """ decode: raises ValueError if invalid varint is provided """
        value = b'\xff\xff\xff'
        with pytest.raises(ValueError) as excinfo:
            decode(value)
        assert 'Invalid varint provided' in str(excinfo.value)


class EncodeTestCase:

    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_encode_valid(self, value):
        """ encode: encodes stuff for all valid cases """
        code = value['encoding']['code']
        actual = make_hash(code, value['length'], value['hex'])
        name = value['encoding']['name']
        assert (hexlify(encode(bytes.fromhex(value['hex']), code, value['length']))
                == hexlify(actual))  # note: round brackets only for line continuation
        assert (hexlify(encode(bytes.fromhex(value['hex']), name, value['length']))
                == hexlify(actual))  # note: round brackets only for line continuation

    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_encode_no_length(self, value):
        """ encode: encodes stuff for all valid cases when length is not given """
        code = value['encoding']['code']
        actual = make_hash(code, value['length'], value['hex'])
        name = value['encoding']['name']
        assert hexlify(encode(bytes.fromhex(value['hex']), code)) == hexlify(actual)
        assert hexlify(encode(bytes.fromhex(value['hex']), name)) == hexlify(actual)

    def test_encode_unequal_length(self):
        """ encode: raises ValueError when unequal lengths are given """
        value = VALID_TABLE[-1]
        code = value['encoding']['code']

        with pytest.raises(ValueError) as excinfo:
            assert encode(bytes.fromhex(value['hex']), code, value['length'] + 1)
        assert 'digest length should be equal' in str(excinfo.value)

    @pytest.mark.parametrize('value', INVALID_BYTE_TYPES)
    def test_encode_invalid_type(self, value):
        """ encode: raises TypeError when invalid type is given """
        with pytest.raises(TypeError) as excinfo:
            encode(value, 0x11)
        assert 'must be a bytes object' in str(excinfo.value)


class IsValidTestCase:

    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_is_valid_valid(self, value):
        """ is_valid: returns True for all valid cases """
        assert is_valid(make_hash(value['encoding']['code'], value['length'], value['hex']))

    @pytest.mark.parametrize('value', INVALID_TABLE)
    def test_is_valid_invalid(self, value):
        """ is_valid: returns False for all invalid cases """
        assert not is_valid(make_hash(value['code'], value['length'], value['hex']))


class GetPrefixTestCase:
    def test_get_prefix_valid(self):
        """ get_prefix: returns valid prefix """
        multihash = encode(b'foo', 0x11, 3)
        prefix = get_prefix(multihash)
        assert hexlify(prefix).decode() == '1103'

    def test_get_prefix_invalid(self):
        """ get_prefix: raises ValueError for invalid cases """
        with pytest.raises(ValueError):
            get_prefix(b'foobar')


def id_digest(data):
    return data


def sha1_digest(data):
    m = hashlib.sha1()
    m.update(data)
    return m.digest()


def sha2_digest(data, length):
    m = getattr(hashlib, 'sha{}'.format(length*8))()
    m.update(data)
    return m.digest()


def sha3_digest(data, length):
    m = getattr(hashlib, 'sha3_{}'.format(length*8))()
    m.update(data)
    return m.digest()


def shake_digest(data, length):
    m = getattr(hashlib, 'shake_{}'.format(length*4))()
    m.update(data)
    return m.digest(length)


def blake2_digest(data, variant, length):
    assert variant in ('b', 's')
    m = getattr(hashlib, 'blake2{}'.format(variant))(digest_size=length)
    m.update(data)
    return m.digest()


def skein_digest(data, variant, length):
    assert variant in (256, 512, 1024)
    m = getattr(skein, 'skein{}'.format(variant))(digest_bits=length*8)
    m.update(data)
    return m.digest()


DIGEST_DATA = {
    prefix: tuple(
        {'data': b"Bytes to be hashed.", 'length': length}
        for length in (entry.get('length') for entry in HASH_TABLE
                       if str(entry['hash']).startswith(prefix))
    )
    for prefix in ('id', 'sha1', 'sha2', 'sha3', 'shake',
                   'blake2b', 'blake2s', 'Skein256', 'Skein512', 'Skein1024')
}


class DigestTestCase:

    @pytest.mark.parametrize('value', DIGEST_DATA['id'])
    def test_id(self, value):
        """ test_id: id hash works """
        hash_fn = 'id'
        data, _ = (value['data'], value['length'])
        assert encode(id_digest(data), hash_fn) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['sha1'])
    def test_sha1(self, value):
        """ test_sha1: sha1 hash works """
        hash_fn = 'sha1'
        data, _ = (value['data'], value['length'])
        assert encode(sha1_digest(data), hash_fn) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['sha2'])
    def test_sha2(self, value):
        """ test_sha2: sha2 hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'sha2-{}'.format(length*8)
        assert encode(sha2_digest(data, length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['sha3'])
    def test_sha3(self, value):
        """ test_sha3: sha3 hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'sha3-{}'.format(length*8)
        assert encode(sha3_digest(data, length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['shake'])
    def test_shake(self, value):
        """ test_shake: shake hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'shake-{}'.format(length*4)
        assert encode(shake_digest(data, length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['blake2b'])
    def test_blake2b(self, value):
        """ test_blake2b: blake2b hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'blake2b-{}'.format(length*8)
        assert encode(blake2_digest(data, 'b', length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['blake2s'])
    def test_blake2s(self, value):
        """ test_blake2s: blake2s hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'blake2s-{}'.format(length*8)
        assert encode(blake2_digest(data, 's', length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['Skein256'])
    def test_skein256(self, value):
        """ test_skein256: Skein256 hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'Skein256-{}'.format(length*8)
        assert encode(skein_digest(data, 256, length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['Skein512'])
    def test_skein512(self, value):
        """ test_skein256: Skein512 hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'Skein512-{}'.format(length*8)
        assert encode(skein_digest(data, 512, length), hash_fn, length) == digest(data, hash_fn)

    @pytest.mark.parametrize('value', DIGEST_DATA['Skein1024'])
    def test_skein1024(self, value):
        """ test_skein256: Skein1024 hash works """
        data, length = (value['data'], value['length'])
        hash_fn = 'Skein1024-{}'.format(length*8)
        assert encode(skein_digest(data, 1024, length), hash_fn, length) == digest(data, hash_fn)
