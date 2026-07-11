import csv
import os

from multihash.constants import HASH_CODES
from multihash.funcs import Func


def test_spec_table_completeness():
    """Every multihash entry in table.csv should be in HASH_CODES and Func."""
    spec_path = os.path.join(os.path.dirname(__file__), "..", "spec", "multicodec", "table.csv")

    with open(spec_path, "r") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        for row in reader:
            if row["tag"].strip() != "multihash":
                continue

            name = row["name"].strip()
            code = int(row["code"].strip(), 16)

            assert name in HASH_CODES, f"Missing hash in HASH_CODES: {name} (0x{code:x})"
            assert HASH_CODES[name] == code, f"Code mismatch in HASH_CODES for {name}"

            # Check if any Enum member has this value
            values = [f.value for f in Func]
            assert code in values, f"Missing code in Func enum for {name} (0x{code:x})"
