"""Custom exception hierarchy for multihash operations."""


class MultihashError(Exception):
    """Base exception for multihash errors."""

    pass


class InvalidMultihashError(MultihashError):
    """Raised when multihash is invalid."""

    pass


class UnsupportedCodeError(MultihashError):
    """Raised when hash code is not supported."""

    pass


class HashComputationError(MultihashError):
    """Raised when hash computation fails."""

    pass


class TruncationError(MultihashError):
    """Raised when truncation length is invalid."""

    pass
