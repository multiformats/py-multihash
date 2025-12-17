"""Top-level package for py-multihash."""

__author__ = """Dhruv Baldawa"""
__email__ = "dhruv@dhruvb.com"
__version__ = "3.0.0"

from .exceptions import (
    HashComputationError,
    InvalidMultihashError,
    MultihashError,
    TruncationError,
    UnsupportedCodeError,
)
from .funcs import Func, FuncReg, IdentityHash, ShakeHash
from .multihash import (
    Multihash,
    MultihashSet,
    coerce_code,
    decode,
    digest,
    encode,
    from_b58_string,
    from_hex_string,
    from_json,
    get_prefix,
    is_app_code,
    is_valid,
    is_valid_code,
    sum,
    sum_stream,
    to_b58_string,
    to_hex_string,
)

__all__ = [
    "Func",
    "FuncReg",
    "HashComputationError",
    "IdentityHash",
    "InvalidMultihashError",
    "Multihash",
    "MultihashError",
    "MultihashSet",
    "ShakeHash",
    "TruncationError",
    "UnsupportedCodeError",
    "coerce_code",
    "decode",
    "digest",
    "encode",
    "from_b58_string",
    "from_hex_string",
    "from_json",
    "get_prefix",
    "is_app_code",
    "is_valid",
    "is_valid_code",
    "sum",
    "sum_stream",
    "to_b58_string",
    "to_hex_string",
]
