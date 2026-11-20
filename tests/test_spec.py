"""Spec compliance tests against multicodec table.csv."""

import csv
import os

from multihash.constants import CODE_HASHES, HASH_CODES
from multihash.funcs import Func

# Codes present locally but tagged ``hash`` (not ``multihash``) in multicodec/table.csv.
# Kept for compatibility; reverse completeness checks allow these intentionally.
_NON_MULTIHASH_LOCAL_ALLOWLIST = {
    0x22: "murmur3-128",
    0x23: "murmur3-32",
}


def _load_multihash_spec():
    """Return {code: name} for rows tagged multihash in table.csv."""
    spec_path = os.path.join(os.path.dirname(__file__), "..", "spec", "multicodec", "table.csv")
    expected = {}
    with open(spec_path) as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        for row in reader:
            if row["tag"].strip() != "multihash":
                continue
            name = row["name"].strip()
            code = int(row["code"].strip(), 16)
            expected[code] = name
    return expected


def test_spec_table_completeness():
    """Every multihash entry in table.csv should be in HASH_CODES and Func."""
    expected = _load_multihash_spec()
    func_values = {f.value for f in Func}

    for code, name in expected.items():
        assert name in HASH_CODES, f"Missing hash in HASH_CODES: {name} (0x{code:x})"
        assert HASH_CODES[name] == code, f"Code mismatch in HASH_CODES for {name}"
        assert code in func_values, f"Missing code in Func enum for {name} (0x{code:x})"


def test_spec_no_unexpected_local_entries():
    """Local tables must not contain codes absent from the multihash CSV (except allowlist)."""
    expected = _load_multihash_spec()

    for name, code in HASH_CODES.items():
        if code in _NON_MULTIHASH_LOCAL_ALLOWLIST:
            assert _NON_MULTIHASH_LOCAL_ALLOWLIST[code] == name, (
                f"Allowlisted code 0x{code:x} expected name {_NON_MULTIHASH_LOCAL_ALLOWLIST[code]!r}, got {name!r}"
            )
            continue
        assert code in expected, f"Local hash {name!r} (0x{code:x}) not defined as tag=multihash in the spec"
        assert expected[code] == name, f"Name mismatch for 0x{code:x}: local {name!r}, spec {expected[code]!r}"

    for code, name in CODE_HASHES.items():
        if code in _NON_MULTIHASH_LOCAL_ALLOWLIST:
            continue
        assert code in expected, f"CODE_HASHES entry {name!r} (0x{code:x}) not in multihash spec"

    for func in Func:
        if func.value in _NON_MULTIHASH_LOCAL_ALLOWLIST:
            continue
        assert func.value in expected, f"Func.{func.name} (0x{func.value:x}) not in multihash spec"
