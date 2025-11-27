"""Top-level package for py-multihash."""

__author__ = """Dhruv Baldawa"""
__email__ = "dhruv@dhruvb.com"
__version__ = "2.0.0"

from .multihash import (
    Multihash,
    coerce_code,
    decode,
    encode,
    from_b58_string,
    from_hex_string,
    get_prefix,
    is_app_code,
    is_valid,
    is_valid_code,
    to_b58_string,
    to_hex_string,
)

__all__ = [
    "Multihash",
    "coerce_code",
    "decode",
    "encode",
    "from_b58_string",
    "from_hex_string",
    "get_prefix",
    "is_app_code",
    "is_valid",
    "is_valid_code",
    "to_b58_string",
    "to_hex_string",
]
