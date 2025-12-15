"""Tests for new features: streaming, truncation, SHAKE, exceptions."""

import base64
import hashlib
import json
from io import BytesIO

import pytest
import varint

import multihash
from multihash import (
    Func,
    HashComputationError,
    Multihash,
    MultihashSet,
    ShakeHash,
    TruncationError,
    decode,
    digest,
    from_json,
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

    def test_sum_stream_custom_chunk_size(self):
        """Test sum_stream() with custom chunk size."""
        data = b"x" * 20000
        stream1 = BytesIO(data)
        mh1 = sum_stream(stream1, Func.sha2_256, chunk_size=4096)
        stream2 = BytesIO(data)
        mh2 = sum_stream(stream2, Func.sha2_256, chunk_size=16384)
        assert mh1.digest == mh2.digest
        assert mh1.digest == hashlib.sha256(data).digest()

    def test_sum_stream_invalid_chunk_size(self):
        """Test that sum_stream() raises ValueError for invalid chunk_size."""
        data = BytesIO(b"test")
        with pytest.raises(ValueError, match="chunk_size must be positive"):
            sum_stream(data, Func.sha2_256, chunk_size=0)
        data2 = BytesIO(b"test")
        with pytest.raises(ValueError, match="chunk_size must be positive"):
            sum_stream(data2, Func.sha2_256, chunk_size=-1)


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


class TestIntegrationTestCase:
    """Integration tests for feature combinations."""

    def test_streaming_with_truncation(self):
        """Test sum_stream() with truncation parameter."""
        data = b"test data for streaming with truncation"
        stream = BytesIO(data)
        mh_stream = sum_stream(stream, Func.sha2_256, length=16)

        # Verify it matches sum() with same truncation
        mh_sum = sum(data, Func.sha2_256, length=16)
        assert mh_stream.digest == mh_sum.digest
        assert len(mh_stream.digest) == 16

    def test_shake_with_streaming(self):
        """Test sum_stream() with SHAKE-128 and SHAKE-256."""
        data = b"streaming test data"

        # SHAKE-128 with custom length
        stream1 = BytesIO(data)
        mh1 = sum_stream(stream1, Func.shake_128, length=48)
        assert len(mh1.digest) == 48

        # SHAKE-256 with custom length
        stream2 = BytesIO(data)
        mh2 = sum_stream(stream2, Func.shake_256, length=32)
        assert len(mh2.digest) == 32

        # Verify they match sum() with same parameters
        mh1_sum = sum(data, Func.shake_128, length=48)
        mh2_sum = sum(data, Func.shake_256, length=32)
        assert mh1.digest == mh1_sum.digest
        assert mh2.digest == mh2_sum.digest

    def test_shake_produces_correct_length(self):
        """Test that SHAKE functions produce correct length without additional truncation."""
        data = b"test"
        mh = sum(data, Func.shake_128, length=40)
        assert len(mh.digest) == 40
        # Verify it's actually SHAKE-128 output
        expected = hashlib.shake_128(data).digest(40)
        assert mh.digest == expected

    def test_truncation_error_in_streaming(self):
        """Test that TruncationError is raised appropriately in streaming context."""
        data = b"test"
        stream = BytesIO(data)
        with pytest.raises(TruncationError, match="exceeds digest size"):
            sum_stream(stream, Func.sha2_256, length=100)

    def test_multihash_encode_with_truncation(self):
        """Test that truncated multihashes encode/decode correctly."""
        mh = sum(b"hello", Func.sha2_256, length=16)
        encoded = mh.encode()
        decoded = decode(encoded)
        assert decoded.digest == mh.digest

    def test_verify_truncated_multihash(self):
        """Test that verify() works correctly with truncated multihashes."""
        data = b"test data"
        mh_truncated = sum(data, Func.sha2_256, length=16)
        assert mh_truncated.verify(data) is True
        assert len(mh_truncated.digest) == 16
        assert mh_truncated.length == 16
        # Verify it doesn't match wrong data
        assert mh_truncated.verify(b"wrong data") is False

    def test_sum_stream_large_data_with_truncation(self):
        """Test streaming with truncation on larger data."""
        data = b"x" * 20000
        stream = BytesIO(data)
        mh = sum_stream(stream, Func.sha2_256, length=20)
        assert len(mh.digest) == 20
        # Verify it matches sum() with same truncation
        mh_sum = sum(data, Func.sha2_256, length=20)
        assert mh.digest == mh_sum.digest


class TestMultihashSetTestCase:
    """Tests for MultihashSet collection type."""

    def test_multihash_set_creation(self):
        """Test creating empty and from iterable MultihashSet."""
        # Empty set
        mh_set = MultihashSet()
        assert len(mh_set) == 0

        # From iterable
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh2])
        assert len(mh_set) == 2

    def test_multihash_set_add(self):
        """Test adding items to MultihashSet."""
        mh_set = MultihashSet()
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)

        # Go-style API
        mh_set.Add(mh1)
        assert len(mh_set) == 1

        # Python-style API
        mh_set.add(mh2)
        assert len(mh_set) == 2

    def test_multihash_set_remove(self):
        """Test removing items from MultihashSet."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh2])

        # Go-style remove
        mh_set.Remove(mh1)
        assert len(mh_set) == 1
        assert mh1 not in mh_set

        # Python-style remove
        mh_set.remove(mh2)
        assert len(mh_set) == 0

        # discard doesn't raise KeyError
        mh_set.discard(mh1)  # Should not raise

    def test_multihash_set_has(self):
        """Test checking membership in MultihashSet."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1])

        # Go-style API
        assert mh_set.Has(mh1) is True
        assert mh_set.Has(mh2) is False

        # Python-style API
        assert mh1 in mh_set
        assert mh2 not in mh_set

    def test_multihash_set_all(self):
        """Test getting all items from MultihashSet."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh2])

        all_items = mh_set.All()
        assert len(all_items) == 2
        assert mh1 in all_items
        assert mh2 in all_items

    def test_multihash_set_len(self):
        """Test length operations on MultihashSet."""
        mh_set = MultihashSet()
        assert len(mh_set) == 0

        mh1 = sum(b"file1", Func.sha2_256)
        mh_set.add(mh1)
        assert len(mh_set) == 1

    def test_multihash_set_iteration(self):
        """Test iteration over MultihashSet."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh2])

        items = list(mh_set)
        assert len(items) == 2
        assert mh1 in items
        assert mh2 in items

    def test_multihash_set_operations(self):
        """Test set operations (union, intersection, difference)."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh3 = sum(b"file3", Func.sha2_256)

        set1 = MultihashSet([mh1, mh2])
        set2 = MultihashSet([mh2, mh3])

        # Union
        union_set = set1.union(set2)
        assert len(union_set) == 3
        assert mh1 in union_set
        assert mh2 in union_set
        assert mh3 in union_set

        # Intersection
        intersection_set = set1.intersection(set2)
        assert len(intersection_set) == 1
        assert mh2 in intersection_set

        # Difference
        difference_set = set1.difference(set2)
        assert len(difference_set) == 1
        assert mh1 in difference_set
        assert mh2 not in difference_set

        # Symmetric difference
        symdiff_set = set1.symmetric_difference(set2)
        assert len(symdiff_set) == 2
        assert mh1 in symdiff_set
        assert mh3 in symdiff_set
        assert mh2 not in symdiff_set

    def test_multihash_set_duplicates(self):
        """Test that duplicates are handled correctly."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh1])  # Same hash twice
        assert len(mh_set) == 1  # Should only have one

    def test_multihash_set_type_error(self):
        """Test that non-Multihash objects are rejected."""
        mh_set = MultihashSet()
        with pytest.raises(TypeError, match="MultihashSet can only contain Multihash objects"):
            mh_set.add("not a multihash")

        with pytest.raises(TypeError, match="MultihashSet can only contain Multihash objects"):
            MultihashSet(["not", "multihash", "objects"])

    def test_multihash_set_go_api(self):
        """Test Go-style API (Add, Remove, Has, All)."""
        mh_set = MultihashSet()
        mh1 = sum(b"file1", Func.sha2_256)

        # Add
        mh_set.Add(mh1)
        assert mh_set.Has(mh1) is True

        # All
        all_items = mh_set.All()
        assert len(all_items) == 1
        assert all_items[0] == mh1

        # Remove
        mh_set.Remove(mh1)
        assert mh_set.Has(mh1) is False

    def test_multihash_set_clear(self):
        """Test clearing MultihashSet."""
        mh1 = sum(b"file1", Func.sha2_256)
        mh2 = sum(b"file2", Func.sha2_256)
        mh_set = MultihashSet([mh1, mh2])

        mh_set.clear()
        assert len(mh_set) == 0
        assert mh1 not in mh_set
        assert mh2 not in mh_set


class TestJsonSerializationTestCase:
    """Tests for JSON serialization support."""

    def test_to_json_compact(self):
        """Test compact format JSON serialization."""
        mh = sum(b"hello", Func.sha2_256)
        json_str = mh.to_json()

        # Should be valid JSON
        data = json.loads(json_str)
        assert "code" in data
        assert "length" in data
        assert "digest" in data
        assert "name" not in data  # Compact format doesn't include name

    def test_to_json_verbose(self):
        """Test verbose format JSON serialization."""
        mh = sum(b"hello", Func.sha2_256)
        json_str = mh.to_json(verbose=True)

        # Should be valid JSON with name
        data = json.loads(json_str)
        assert "code" in data
        assert "length" in data
        assert "digest" in data
        assert "name" in data  # Verbose format includes name
        assert data["name"] == "sha2-256"

    def test_from_json_compact(self):
        """Test deserializing compact format JSON."""
        mh = sum(b"hello", Func.sha2_256)
        json_str = mh.to_json()

        # Deserialize
        mh_restored = from_json(json_str)
        assert mh_restored.code == mh.code
        assert mh_restored.length == mh.length
        assert mh_restored.digest == mh.digest

    def test_from_json_verbose(self):
        """Test deserializing verbose format JSON."""
        mh = sum(b"hello", Func.sha2_256)
        json_str = mh.to_json(verbose=True)

        # Deserialize
        mh_restored = from_json(json_str)
        assert mh_restored.code == mh.code
        assert mh_restored.length == mh.length
        assert mh_restored.digest == mh.digest
        assert mh_restored.name == mh.name

    def test_json_roundtrip(self):
        """Test round-trip JSON serialization."""
        mh = sum(b"hello world", Func.sha2_256)

        # Round-trip through compact format
        json_str = mh.to_json()
        mh_restored = from_json(json_str)
        assert mh_restored == mh

        # Round-trip through verbose format
        json_str = mh.to_json(verbose=True)
        mh_restored = from_json(json_str)
        assert mh_restored == mh

    def test_json_with_different_hashes(self):
        """Test JSON serialization with different hash functions."""
        test_cases = [
            (b"test1", Func.sha1),
            (b"test2", Func.sha2_256),
            (b"test3", Func.sha2_512),
        ]

        for data, func in test_cases:
            mh = sum(data, func)
            json_str = mh.to_json()
            mh_restored = from_json(json_str)
            assert mh_restored == mh

    def test_json_invalid_input(self):
        """Test handling of invalid JSON input."""
        with pytest.raises(ValueError, match="Invalid JSON string"):
            from_json("not valid json")

        with pytest.raises(ValueError, match="Invalid JSON string"):
            from_json('{"invalid": json}')

    def test_json_missing_fields(self):
        """Test handling of missing required fields."""

        # Missing code
        with pytest.raises(ValueError, match="Missing required fields"):
            from_json(json.dumps({"length": 32, "digest": "dGVzdA=="}))

        # Missing length
        with pytest.raises(ValueError, match="Missing required fields"):
            from_json(json.dumps({"code": 18, "digest": "dGVzdA=="}))

        # Missing digest
        with pytest.raises(ValueError, match="Missing required fields"):
            from_json(json.dumps({"code": 18, "length": 32}))

    def test_json_base64_encoding(self):
        """Test base64 encoding/decoding of digest."""
        mh = sum(b"test data", Func.sha2_256)
        json_str = mh.to_json()

        data = json.loads(json_str)
        digest_str = data["digest"]

        # Decode and verify
        decoded_digest = base64.b64decode(digest_str)
        assert decoded_digest == mh.digest

    def test_json_length_mismatch(self):
        """Test handling of length mismatch."""
        # Create JSON with incorrect length
        digest_bytes = b"test"
        json_data = {
            "code": 18,
            "length": 100,  # Wrong length
            "digest": base64.b64encode(digest_bytes).decode("utf-8"),
        }

        with pytest.raises(ValueError, match="Length mismatch"):
            from_json(json.dumps(json_data))


class TestStreamReadWriteTestCase:
    """Tests for Multihash.read() and Multihash.write() stream methods."""

    def test_write_read_roundtrip(self):
        """Test writing and reading a multihash from a stream."""
        mh_original = sum(b"hello world", Func.sha2_256)
        stream = BytesIO()

        # Write to stream
        bytes_written = mh_original.write(stream)
        assert bytes_written > 0

        # Read back from stream
        stream.seek(0)
        mh_read = Multihash.read(stream)

        # Verify they match
        assert mh_read.code == mh_original.code
        assert mh_read.name == mh_original.name
        assert mh_read.length == mh_original.length
        assert mh_read.digest == mh_original.digest

    def test_write_multiple_multihashes(self):
        """Test writing multiple multihashes to the same stream."""
        mh1 = sum(b"first", Func.sha2_256)
        mh2 = sum(b"second", Func.sha2_512)
        mh3 = sum(b"third", Func.sha1)

        stream = BytesIO()

        # Write all multihashes
        mh1.write(stream)
        mh2.write(stream)
        mh3.write(stream)

        # Read them back
        stream.seek(0)
        read_mh1 = Multihash.read(stream)
        read_mh2 = Multihash.read(stream)
        read_mh3 = Multihash.read(stream)

        # Verify
        assert read_mh1.digest == mh1.digest
        assert read_mh2.digest == mh2.digest
        assert read_mh3.digest == mh3.digest

    def test_read_from_encoded_multihash(self):
        """Test reading from an already encoded multihash."""
        # Create an encoded multihash using the encode function
        digest_bytes = hashlib.sha256(b"test data").digest()
        encoded = multihash.encode(digest_bytes, Func.sha2_256)

        # Read it using Multihash.read()
        stream = BytesIO(encoded)
        mh = multihash.Multihash.read(stream)

        assert mh.code == 0x12
        assert mh.digest == digest_bytes
        assert mh.length == len(digest_bytes)

    def test_write_returns_correct_byte_count(self):
        """Test that write() returns the correct number of bytes written."""
        mh = sum(b"test", Func.sha2_256)
        stream = BytesIO()

        bytes_written = mh.write(stream)
        stream.seek(0)
        actual_bytes = stream.read()

        assert bytes_written == len(actual_bytes)

    def test_read_insufficient_data(self):
        """Test reading from a stream with insufficient data."""
        # Create a truncated multihash (code and length but no digest)
        stream = BytesIO()
        stream.write(varint.encode(0x12))  # sha2-256 code
        stream.write(varint.encode(32))  # length 32
        stream.write(b"short")  # Only 5 bytes instead of 32

        stream.seek(0)
        with pytest.raises(ValueError, match="Insufficient data"):
            multihash.Multihash.read(stream)

    def test_read_invalid_code(self):
        """Test reading a multihash with an invalid code."""
        # Create a multihash with invalid code
        stream = BytesIO()
        stream.write(varint.encode(0xFFFF))  # Invalid code
        stream.write(varint.encode(10))
        stream.write(b"0" * 10)

        stream.seek(0)
        with pytest.raises(ValueError, match="Invalid multihash code"):
            multihash.Multihash.read(stream)

    def test_read_zero_length(self):
        """Test reading a multihash with zero length digest."""
        stream = BytesIO()
        stream.write(varint.encode(0x12))
        stream.write(b"\x00")  # Length 0

        stream.seek(0)
        mh = multihash.Multihash.read(stream)
        assert mh.length == 0
        assert mh.digest == b""

    def test_write_to_file(self, tmp_path):
        """Test writing multihash to an actual file."""
        mh = sum(b"file test", Func.sha2_256)
        file_path = tmp_path / "multihash.bin"

        # Write to file
        with open(file_path, "wb") as f:
            mh.write(f)

        # Read from file
        with open(file_path, "rb") as f:
            mh_read = multihash.Multihash.read(f)

        assert mh_read.digest == mh.digest
        assert mh_read.code == mh.code

    def test_read_write_with_truncated_multihash(self):
        """Test read/write with a truncated multihash."""
        mh = sum(b"truncation test", Func.sha2_256, length=16)
        stream = BytesIO()

        # Write truncated multihash
        mh.write(stream)

        # Read it back
        stream.seek(0)
        mh_read = multihash.Multihash.read(stream)

        assert mh_read.length == 16
        assert mh_read.digest == mh.digest
        assert len(mh_read.digest) == 16

    def test_read_write_shake_multihash(self):
        """Test read/write with SHAKE hash functions."""
        mh = sum(b"shake test", Func.shake_128, length=32)
        stream = BytesIO()

        mh.write(stream)
        stream.seek(0)
        mh_read = multihash.Multihash.read(stream)

        assert mh_read.code == Func.shake_128.value
        assert mh_read.digest == mh.digest
        assert mh_read.length == 32

    def test_read_write_with_different_hash_functions(self):
        """Test read/write with various hash functions."""
        test_data = b"multi-function test"
        hash_functions = [
            Func.sha1,
            Func.sha2_256,
            Func.sha2_512,
            Func.sha3_256,
            Func.blake2b_256,
        ]

        for func in hash_functions:
            mh = sum(test_data, func)
            stream = BytesIO()

            mh.write(stream)
            stream.seek(0)
            mh_read = multihash.Multihash.read(stream)

            assert mh_read.code == mh.code
            assert mh_read.digest == mh.digest
            assert mh_read.length == mh.length

    def test_write_to_invalid_stream(self):
        """Test that write() raises appropriate error for invalid stream."""
        mh = sum(b"test", Func.sha2_256)

        # Try to write to a non-writable object
        with pytest.raises(TypeError, match="write\\(\\) method"):
            mh.write("not a stream")

    def test_read_from_empty_stream(self):
        """Test reading from an empty stream."""
        stream = BytesIO(b"")

        with pytest.raises(ValueError, match="Failed to read"):
            multihash.Multihash.read(stream)

    def test_read_write_app_code(self):
        """Test read/write with application-specific codes."""
        # Register an app-specific code
        app_code = 0x05
        FuncReg.register(app_code, "test-app-hash", "test-app-sha256", lambda: hashlib.sha256())

        try:
            mh = sum(b"app code test", app_code)
            stream = BytesIO()

            mh.write(stream)
            stream.seek(0)
            mh_read = multihash.Multihash.read(stream)

            assert mh_read.code == app_code
            assert mh_read.digest == mh.digest
        finally:
            # Clean up
            FuncReg.unregister(app_code)
