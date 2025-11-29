# py-multihash: Python implementation of the multihash specification

"""Tests for funcs module (Func, FuncReg, IdentityHash) and digest function."""

import hashlib

import pytest

from multihash import Func, FuncReg, IdentityHash, Multihash, digest
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
