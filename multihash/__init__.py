# -*- coding: utf-8 -*-

"""Top-level package for py-multihash."""

__author__ = """Dhruv Baldawa"""
__email__ = 'dhruv@dhruvb.com'
__version__ = '2.0.0'

from .multihash import (  # noqa: F401
    Multihash, decode, encode, digest, b58digest,
    to_hex_string, from_hex_string, to_b58_string, from_b58_string,
    is_app_code, coerce_code, is_valid_code, is_valid, get_prefix
)
