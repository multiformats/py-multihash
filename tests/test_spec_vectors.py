"""Official multihash spec vector tests."""

import csv
from binascii import hexlify
from pathlib import Path

import pytest

from multihash import FuncReg, HashComputationError, sum

SPEC_VECTORS = Path(__file__).resolve().parents[1] / "spec" / "multihash" / "tests" / "values" / "test_cases.csv"

# Spec CSV uses "sha3" as an alias for sha3-512 (same as go-multihash).
_ALGORITHM_ALIASES = {
    "sha3": "sha3-512",
}


def _load_cases():
    if not SPEC_VECTORS.is_file():
        pytest.skip(f"spec vectors not found at {SPEC_VECTORS} (init git submodules?)")
    with SPEC_VECTORS.open(newline="") as f:
        reader = csv.reader(f)
        next(reader)  # header
        return list(reader)


@pytest.mark.parametrize("algorithm,bits_str,input_hex,expected_hex", _load_cases())
def test_spec_vectors(algorithm, bits_str, input_hex, expected_hex):
    """Validate sum() against official multihash test vectors.

    The CSV ``input`` column is hashed as UTF-8/ASCII of the hex string itself
    (not as decoded binary), matching go-multihash ``TestSpecVectors``.
    """
    algorithm = _ALGORITHM_ALIASES.get(algorithm, algorithm)
    length_bytes = int(bits_str) // 8
    data = input_hex.encode()

    try:
        FuncReg.get(algorithm)
    except KeyError:
        pytest.skip(f"hash {algorithm} not registered")

    try:
        actual = sum(data, algorithm, length=length_bytes)
    except (HashComputationError, KeyError, ValueError) as exc:
        pytest.skip(f"hash {algorithm} unavailable: {exc}")

    assert hexlify(actual.encode()).decode() == expected_hex
