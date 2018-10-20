#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `multihash` package."""
from binascii import hexlify

import base58
import pytest
import varint

from multihash import (
    encode, decode, from_hex_string, to_hex_string, to_b58_string, from_b58_string, is_app_code, is_valid,
    is_valid_code, get_prefix, coerce_code,
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
        'hex': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e72c26b46b6f8ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e'
    },
)

INVALID_BYTE_TYPES = ('a', 1, 1.0, [], {})
INVALID_STRING_TYPES = (b'a', 1, 1.0, [], {})


def make_hash(code, size, hex_):
    return code.to_bytes((code.bit_length() + 7) // 8, byteorder='big') + \
        size.to_bytes((size.bit_length() + 7) // 8, byteorder='big') + \
        bytes.fromhex(hex_)


class ToHexStringTestCase(object):
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


class FromHexStringTestCase(object):
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


class To58StringTestCase(object):
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


class FromB58StringTestCase(object):
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


class IsAppCodeTestCase(object):
    @pytest.mark.parametrize('value', (0x01, 0x0f, 0x04))
    def test_is_app_code_valid(self, value):
        """ is_app_code: returns True for all valid cases """
        assert is_app_code(value)

    @pytest.mark.parametrize('value', (0x00, 0x11, 0x10, 0xffff))
    def test_is_app_code_invalid(self, value):
        """ is_app_code: returns False for invalid cases """
        assert not is_app_code(value)


class CoerceCodeTestCase(object):
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


class IsValidCodeTestCase(object):
    @pytest.mark.parametrize('value', (0x02, 0x0f, 0x13))
    def test_is_valid_code_valid(self, value):
        """ is_valid_code: returns True for all valid cases """
        assert is_valid_code(value)

    @pytest.mark.parametrize('value', (0x0ff, 0x10, 0x90))
    def test_is_valid_code_invalid(self, value):
        """ is_valid_code: returns False for all invalid cases """
        assert not is_valid_code(value)


class DecodeTestCase(object):
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

class EncodeTestCase(object):
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_encode_valid(self, value):
        """ encode: encodes stuff for all valid cases """
        code = value['encoding']['code']
        actual = make_hash(code, value['length'], value['hex'])
        name = value['encoding']['name']
        assert hexlify(encode(bytes.fromhex(value['hex']), code, value['length'])) == hexlify(actual)
        assert hexlify(encode(bytes.fromhex(value['hex']), name, value['length'])) == hexlify(actual)

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

class IsValidTestCase(object):
    @pytest.mark.parametrize('value', VALID_TABLE)
    def test_is_valid_valid(self, value):
        """ is_valid: returns True for all valid cases """
        assert is_valid(make_hash(value['encoding']['code'], value['length'], value['hex']))

    @pytest.mark.parametrize('value', INVALID_TABLE)
    def test_is_valid_invalid(self, value):
        """ is_valid: returns False for all invalid cases """
        assert not is_valid(make_hash(value['code'], value['length'], value['hex']))


class GetPrefixTestCase(object):
    def test_get_prefix_valid(self):
        """ get_prefix: returns valid prefix """
        multihash = encode(b'foo', 0x11, 3)
        prefix = get_prefix(multihash)
        assert hexlify(prefix).decode() == '1103'

    def test_get_prefix_invalid(self):
        """ get_prefix: raises ValueError for invalid cases """
        with pytest.raises(ValueError):
            get_prefix(b'foobar')
