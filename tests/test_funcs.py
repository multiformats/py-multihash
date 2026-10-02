# py-multihash: Python implementation of the multihash specification

"""Tests for funcs module (Func, FuncReg, IdentityHash) and digest function."""

import hashlib

import pytest

from multihash import Func, FuncReg, HashComputationError, IdentityHash, Multihash, digest
from multihash.constants import HASH_CODES


class FuncTestCase:
    """Tests for the Func IntEnum."""

    def test_values_match_constants(self):
        assert Func.sha2_256 == HASH_CODES["sha2-256"]
        assert Func.identity == HASH_CODES["id"]

    def test_is_int_enum(self):
        assert isinstance(Func.sha2_256, int)
        assert Func(0x12) == Func.sha2_256


class IdentityHashTestCase:
    """Tests for IdentityHash hashlib-compatible class."""

    def test_identity_hash(self):
        h = IdentityHash()
        h.update(b"hello")
        assert h.digest() == b"hello"
        assert h.name == "identity"

    def test_copy(self):
        h1 = IdentityHash()
        h1.update(b"original")
        h2 = h1.copy()
        h2.update(b" modified")
        assert h1.digest() == b"original"
        assert h2.digest() == b"original modified"


class FuncRegTestCase:
    """Tests for FuncReg registry class."""

    def setup_method(self):
        FuncReg.reset()

    def test_get_by_various_types(self):
        assert FuncReg.get(Func.sha2_256) == Func.sha2_256
        assert FuncReg.get("sha2_256") == Func.sha2_256
        assert FuncReg.get(0x12) == Func.sha2_256

    def test_hash_from_func(self):
        h = FuncReg.hash_from_func(Func.sha2_256)
        h.update(b"test")
        assert h.digest() == hashlib.sha256(b"test").digest()

    def test_register_app_specific(self):
        FuncReg.register(0x01, "my_hash", "my_hash", IdentityHash)
        assert 0x01 in FuncReg

    def test_unregister_standard_raises(self):
        with pytest.raises(ValueError):
            FuncReg.unregister(Func.sha2_256)


class DigestTestCase:
    """Tests for the digest() function."""

    def test_digest_sha256(self):
        mh = digest(b"test", Func.sha2_256)
        assert mh.code == 0x12
        assert mh.digest == hashlib.sha256(b"test").digest()

    def test_digest_identity(self):
        mh = digest(b"raw", Func.identity)
        assert mh.digest == b"raw"

    def test_encode_and_verify(self):
        mh = digest(b"hello", Func.sha2_256)
        assert mh.encode()[0] == 0x12
        assert mh.verify(b"hello") is True
        assert mh.verify(b"other") is False

    def test_multihash_construction_styles(self):
        # pymultihash style
        mh1 = Multihash(func=Func.sha2_256, digest=b"x" * 32)
        assert mh1.code == 0x12

        # py-multihash style
        mh2 = Multihash(code=0x12, name="sha2-256", length=32, digest=b"x" * 32)
        assert mh2.code == 0x12


class NewHashFunctionsTestCase:
    """Tests for newly implemented hash functions (Blake3, MurmurHash3, Blake2 variants, etc.)"""

    def test_blake3_available(self):
        """Test that Blake3 is available and works."""
        assert hasattr(Func, "blake3")
        assert Func.blake3 == 0x1E
        mh = digest(b"hello world", "blake3")
        assert mh.code == Func.blake3
        assert len(mh.digest) == 32  # Blake3 default is 32 bytes

    def test_blake3_variable_lengths(self):
        """BLAKE3 supports variable output up to 128 bytes."""
        import blake3 as blake3_mod

        data = b"foo"
        for length in (32, 64, 128):
            mh = digest(data, Func.blake3, length=length)
            assert len(mh.digest) == length
            expected = blake3_mod.blake3(data).digest(length)
            assert mh.digest == expected

        assert FuncReg.is_variable_size(Func.blake3) is True
        assert FuncReg.default_lengths[Func.blake3] == 32

        with pytest.raises(HashComputationError):
            digest(data, Func.blake3, length=129)

    def test_keccak_available(self):
        """Legacy Keccak hashes register when pycryptodome is installed."""
        pytest.importorskip("Crypto.Hash.keccak")
        from Crypto.Hash import keccak

        mh = digest(b"hello", Func.keccak_256)
        assert mh.code == Func.keccak_256
        assert len(mh.digest) == 32
        expected = keccak.new(digest_bits=256)
        expected.update(b"hello")
        assert mh.digest == expected.digest()

        for func, bits in (
            (Func.keccak_224, 224),
            (Func.keccak_384, 384),
            (Func.keccak_512, 512),
        ):
            mh_v = digest(b"hello", func)
            assert len(mh_v.digest) == bits // 8

    def test_murmur3_128_available(self):
        """Test that MurmurHash3-128 is available and works."""
        assert hasattr(Func, "murmur3_128")
        assert Func.murmur3_128 == 0x22
        mh = digest(b"test", "murmur3-128")
        assert mh.code == Func.murmur3_128
        assert len(mh.digest) == 16  # 128 bits = 16 bytes

    def test_murmur3_32_available(self):
        """Test that MurmurHash3-32 is available and works."""
        assert hasattr(Func, "murmur3_32")
        assert Func.murmur3_32 == 0x23
        mh = digest(b"test", "murmur3-32")
        assert mh.code == Func.murmur3_32
        assert len(mh.digest) == 4  # 32 bits = 4 bytes

    def test_blake2b_variants_sample(self):
        """Test a sample of Blake2b variants."""
        # Test blake2b-8 (1 byte)
        mh8 = digest(b"test", "blake2b-8")
        assert len(mh8.digest) == 1

        # Test blake2b-128 (16 bytes)
        mh128 = digest(b"test", "blake2b-128")
        assert len(mh128.digest) == 16

        # Test blake2b-256 (32 bytes)
        mh256 = digest(b"test", "blake2b-256")
        assert len(mh256.digest) == 32

        # Test blake2b-512 (64 bytes)
        mh512 = digest(b"test", "blake2b-512")
        assert len(mh512.digest) == 64

    def test_blake2s_variants_sample(self):
        """Test a sample of Blake2s variants."""
        # Test blake2s-8 (1 byte)
        mh8 = digest(b"test", "blake2s-8")
        assert len(mh8.digest) == 1

        # Test blake2s-128 (16 bytes)
        mh128 = digest(b"test", "blake2s-128")
        assert len(mh128.digest) == 16

        # Test blake2s-256 (32 bytes)
        mh256 = digest(b"test", "blake2s-256")
        assert len(mh256.digest) == 32

    def test_dbl_sha2_256(self):
        """Test double SHA-256 (Bitcoin hash)."""
        assert hasattr(Func, "dbl_sha2_256")
        data = b"test"
        mh = digest(data, "dbl-sha2-256")
        assert len(mh.digest) == 32

        # Verify it's actually double hashing
        first_hash = hashlib.sha256(data).digest()
        expected = hashlib.sha256(first_hash).digest()
        assert mh.digest == expected

    def test_sha2_extended_variants(self):
        """Test additional SHA2 variants."""
        # SHA2-224
        mh224 = digest(b"test", "sha2-224")
        assert len(mh224.digest) == 28

        # SHA2-384
        mh384 = digest(b"test", "sha2-384")
        assert len(mh384.digest) == 48

    def test_sha2_256_trunc254_padded(self):
        """Test SHA2-256 truncated to 254 bits."""
        assert hasattr(Func, "sha2_256_trunc254_padded")
        mh = digest(b"test", "sha2-256-trunc254-padded")
        assert len(mh.digest) == 31  # 254 bits = 31 bytes

    def test_ripemd_variants_in_enum(self):
        """Test that RIPEMD variants are in Func enum."""
        assert hasattr(Func, "ripemd_128")
        assert hasattr(Func, "ripemd_160")
        assert hasattr(Func, "ripemd_256")
        assert hasattr(Func, "ripemd_320")

    def test_md4_in_enum(self):
        """Test that MD4 is in Func enum."""
        assert hasattr(Func, "md4")
        assert Func.md4 == 0xD4

    def test_blake2_variants_deterministic(self):
        """Test that Blake2 variants produce consistent results."""
        data = b"test data"
        mh1 = digest(data, "blake2b-128")
        mh2 = digest(data, "blake2b-128")
        assert mh1.digest == mh2.digest

    def test_murmur3_deterministic(self):
        """Test that MurmurHash3 produces consistent results."""
        data = b"test data"
        mh1 = digest(data, "murmur3-128")
        mh2 = digest(data, "murmur3-128")
        assert mh1.digest == mh2.digest


class VariableSizeRegistryTestCase:
    """Tests for FuncReg.register_variable_size and default_lengths."""

    def test_shake_defaults_in_default_lengths(self):
        assert FuncReg.default_lengths[Func.shake_128] == 32
        assert FuncReg.default_lengths[Func.shake_256] == 64
        assert FuncReg.is_variable_size(Func.shake_128) is True
        assert FuncReg.is_variable_size(Func.sha2_256) is False

    def test_fixed_hash_default_length(self):
        assert FuncReg.default_lengths[Func.sha2_256] == 32

    def test_register_variable_size_custom(self):
        def factory(size_hint: int):
            length = 16 if size_hint < 0 else size_hint
            if length <= 0 or length > 32:
                return None

            class H:
                name = "test-var"
                digest_size = length

                def __init__(self):
                    self._data = b""

                def update(self, data):
                    self._data += data

                def digest(self):
                    return (self._data + b"\x00" * length)[:length]

            return H()

        code = 0x07
        try:
            FuncReg.register_variable_size(code, "test-var", factory, "test-var")
            assert FuncReg.default_lengths[code] == 16
            assert FuncReg.is_variable_size(code) is True
            h = FuncReg.hash_from_func(code, length=8)
            assert h.digest_size == 8
        finally:
            FuncReg.unregister(code)
