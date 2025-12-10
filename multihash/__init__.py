"""Top-level package for py-multihash."""

from typing import TYPE_CHECKING

__author__ = """Dhruv Baldawa"""
__email__ = "dhruv@dhruvb.com"
__version__ = "2.0.0"

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

# Explicitly expose types for static type checkers
if TYPE_CHECKING:
    from .funcs import Func as Func
    from .funcs import FuncReg as FuncReg
    from .funcs import IdentityHash as IdentityHash
    from .funcs import ShakeHash as ShakeHash
    from .multihash import Multihash as Multihash
    from .multihash import MultihashSet as MultihashSet

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
