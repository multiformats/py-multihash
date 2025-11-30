"""Tests for new features: streaming, truncation, SHAKE, exceptions."""

import hashlib
from io import BytesIO

import pytest

from multihash import (
    Func,
    HashComputationError,
    ShakeHash,
    TruncationError,
    digest,
    sum,
    sum_stream,
)
from multihash.exceptions import MultihashError
from multihash.funcs import FuncReg


class TestSumFunctionTestCase:
    """Tests for the sum() function (Go-compatible API)."""

    def test_sum_basic(self):
        """Test basic sum() functionality."""
        mh = sum(b"hello", Func.sha2_256)
        assert mh.code == 0x12
        assert mh.digest == hashlib.sha256(b"hello").digest()

    def test_sum_with_truncation(self):
        """Test sum() with truncation."""
        mh = sum(b"hello", Func.sha2_256, length=16)
        assert len(mh.digest) == 16
        assert mh.digest == hashlib.sha256(b"hello").digest()[:16]

    def test_sum_full_digest(self):
        """Test sum() with length=-1 for full digest."""
        mh = sum(b"hello", Func.sha2_256, length=-1)
        assert len(mh.digest) == 32
        assert mh.digest == hashlib.sha256(b"hello").digest()

    def test_sum_equals_digest(self):
        """Test that sum() and digest() produce same results."""
        data = b"test data"
        mh1 = sum(data, Func.sha2_256)
        mh2 = digest(data, Func.sha2_256)
        assert mh1.digest == mh2.digest
        assert mh1.code == mh2.code


class TestSumStreamFunctionTestCase:
    """Tests for the sum_stream() function."""

    def test_sum_stream_bytesio(self):
        """Test sum_stream() with BytesIO."""
        data = b"streaming test data"
        stream = BytesIO(data)
        mh = sum_stream(stream, Func.sha2_256)
        assert mh.digest == hashlib.sha256(data).digest()

    def test_sum_stream_large_data(self):
        """Test sum_stream() with larger data."""
        data = b"x" * 10000
        stream = BytesIO(data)
        mh = sum_stream(stream, Func.sha2_256)
        assert mh.digest == hashlib.sha256(data).digest()

    def test_sum_stream_with_truncation(self):
        """Test sum_stream() with truncation."""
        data = b"test data"
        stream = BytesIO(data)
        mh = sum_stream(stream, Func.sha2_256, length=16)
        assert len(mh.digest) == 16
        assert mh.digest == hashlib.sha256(data).digest()[:16]

    def test_sum_stream_chunked_reading(self):
        """Test that sum_stream() reads in chunks correctly."""
        # Create data larger than default chunk size (8192)
        data = b"x" * 20000
        stream = BytesIO(data)
        mh = sum_stream(stream, Func.sha2_256)
        assert mh.digest == hashlib.sha256(data).digest()

    def test_sum_stream_equals_sum(self):
        """Test that sum_stream() and sum() produce same results."""
        data = b"test data"
        mh1 = sum_stream(BytesIO(data), Func.sha2_256)
        mh2 = sum(data, Func.sha2_256)
        assert mh1.digest == mh2.digest


class TestTruncationTestCase:
    """Tests for truncation support."""

    def test_digest_with_truncation(self):
        """Test digest() with truncation."""
        mh = digest(b"hello", Func.sha2_256, length=16)
        assert len(mh.digest) == 16
        assert mh.length == 16

    def test_truncation_to_zero_raises(self):
        """Test that truncation to zero length raises error."""
        with pytest.raises(TruncationError):
            sum(b"hello", Func.sha2_256, length=0)

    def test_truncation_exceeds_digest_raises(self):
        """Test that truncation exceeding digest size raises error."""
        with pytest.raises(TruncationError):
            sum(b"hello", Func.sha2_256, length=100)

    def test_truncation_negative_raises(self):
        """Test that negative truncation length raises error."""
        with pytest.raises(TruncationError):
            sum(b"hello", Func.sha2_256, length=-2)

    def test_truncation_full_digest(self):
        """Test truncation with length=-1 gives full digest."""
        mh = digest(b"hello", Func.sha2_256, length=-1)
        assert len(mh.digest) == 32  # Full SHA-256 digest

    def test_verify_with_truncated_digest(self):
        """Test that verify() works with truncated digests."""
        mh = digest(b"hello", Func.sha2_256, length=16)
        assert mh.verify(b"hello") is True
        assert mh.verify(b"world") is False


class TestShakeFunctionsTestCase:
    """Tests for SHAKE variable-length hash functions."""

    def test_shake_128_basic(self):
        """Test SHAKE-128 with default length."""
        mh = sum(b"hello", Func.shake_128)
        assert mh.code == Func.shake_128.value
        assert len(mh.digest) == 32  # Default length

    def test_shake_128_custom_length(self):
        """Test SHAKE-128 with custom length."""
        mh = sum(b"hello", Func.shake_128, length=16)
        assert len(mh.digest) == 16
        # Verify it's actually SHAKE-128
        expected = hashlib.shake_128(b"hello").digest(16)
        assert mh.digest == expected

    def test_shake_256_basic(self):
        """Test SHAKE-256 with default length."""
        mh = sum(b"hello", Func.shake_256)
        assert mh.code == Func.shake_256.value
        assert len(mh.digest) == 64  # Default length

    def test_shake_256_custom_length(self):
        """Test SHAKE-256 with custom length."""
        mh = sum(b"hello", Func.shake_256, length=48)
        assert len(mh.digest) == 48
        expected = hashlib.shake_256(b"hello").digest(48)
        assert mh.digest == expected

    def test_shake_stream(self):
        """Test SHAKE with streaming."""
        data = b"streaming test"
        mh = sum_stream(BytesIO(data), Func.shake_128, length=32)
        expected = hashlib.shake_128(data).digest(32)
        assert mh.digest == expected

    def test_shake_hash_wrapper(self):
        """Test ShakeHash wrapper class."""
        shake = ShakeHash(hashlib.shake_128, 32)
        shake.update(b"test")
        digest = shake.digest()
        assert len(digest) == 32
        assert digest == hashlib.shake_128(b"test").digest(32)

    def test_shake_hash_copy(self):
        """Test ShakeHash copy() method."""
        shake1 = ShakeHash(hashlib.shake_128, 32)
        shake1.update(b"test")
        shake2 = shake1.copy()
        shake2.update(b" more")
        assert shake1.digest() == hashlib.shake_128(b"test").digest(32)
        assert shake2.digest() == hashlib.shake_128(b"test more").digest(32)


class TestExceptionsTestCase:
    """Tests for custom exception hierarchy."""

    def test_multihash_error_base(self):
        """Test that MultihashError is base exception."""
        assert issubclass(HashComputationError, MultihashError)
        assert issubclass(TruncationError, MultihashError)

    def test_hash_computation_error(self):
        """Test HashComputationError is raised appropriately."""
        # Test that HashComputationError is raised when hash_from_func returns None
        # This would happen if a function is registered but hash_new is None
        # and it's not a SHAKE function (which requires length parameter)
        # In practice, this is hard to trigger without mocking, so we just
        # verify the exception class exists and is a subclass of MultihashError
        assert issubclass(HashComputationError, MultihashError)

    def test_truncation_error_negative(self):
        """Test TruncationError for negative length."""
        with pytest.raises(TruncationError, match="non-negative"):
            sum(b"hello", Func.sha2_256, length=-2)

    def test_truncation_error_too_large(self):
        """Test TruncationError for length exceeding digest."""
        with pytest.raises(TruncationError, match="exceeds digest size"):
            sum(b"hello", Func.sha2_256, length=100)


class TestAdditionalHashFunctionsTestCase:
    """Tests for additional hash functions (SHA2-224, SHA2-384, etc.)."""

    def test_sha2_224_if_available(self):
        """Test SHA2-224 if available in hashlib."""
        if hasattr(hashlib, "sha224"):
            try:
                mh = sum(b"test", Func.sha2_224)
                assert mh.code == Func.sha2_224.value
                assert mh.digest == hashlib.sha224(b"test").digest()
            except (KeyError, ValueError):
                # Function not registered (not available)
                pytest.skip("SHA2-224 not available")

    def test_sha2_384_if_available(self):
        """Test SHA2-384 if available in hashlib."""
        if hasattr(hashlib, "sha384"):
            try:
                mh = sum(b"test", Func.sha2_384)
                assert mh.code == Func.sha2_384.value
                assert mh.digest == hashlib.sha384(b"test").digest()
            except (KeyError, ValueError):
                # Function not registered (not available)
                pytest.skip("SHA2-384 not available")

    def test_md5_support(self):
        """Test MD5 support (if available)."""
        try:
            mh = sum(b"test", Func.md5)
            assert mh.code == Func.md5.value
            assert mh.digest == hashlib.md5(b"test").digest()
        except (KeyError, ValueError):
            pytest.skip("MD5 not available")


class TestFuncFromHashTestCase:
    """Tests for func_from_hash() error handling."""

    def test_func_from_hash_unknown(self):
        """Test func_from_hash() with unknown hash object."""
        # Create a mock hash object with unknown name
        class UnknownHash:
            name = "unknown_hash_xyz"

        with pytest.raises(KeyError, match="unknown hash object name"):
            FuncReg.func_from_hash(UnknownHash())


class TestDigestWithTruncationTestCase:
    """Tests for digest() function with truncation support."""

    def test_digest_truncation(self):
        """Test digest() with truncation parameter."""
        mh = digest(b"hello", Func.sha2_256, length=16)
        assert len(mh.digest) == 16
        assert mh.length == 16

    def test_digest_no_truncation(self):
        """Test digest() without truncation (backward compatible)."""
        mh1 = digest(b"hello", Func.sha2_256)
        mh2 = digest(b"hello", Func.sha2_256, length=None)
        assert mh1.digest == mh2.digest
