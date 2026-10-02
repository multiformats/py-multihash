"""Benchmark tests for core multihash operations.

Excluded from default ``make test`` / tox core runs via the ``benchmark`` marker.
Run explicitly with::

    pytest -m benchmark tests/test_benchmarks.py
"""

import pytest

from multihash import Func, decode, sum

BENCH_DATA = b"benchmark test data for multihash operations" * 100

pytestmark = pytest.mark.benchmark


def test_bench_sum_sha256(benchmark):
    benchmark(sum, BENCH_DATA, Func.sha2_256)


def test_bench_sum_sha512(benchmark):
    benchmark(sum, BENCH_DATA, Func.sha2_512)


def test_bench_sum_blake3(benchmark):
    benchmark(sum, BENCH_DATA, Func.blake3)


@pytest.mark.parametrize("bits", [8, 128, 256, 384, 512])
def test_bench_sum_blake2b(benchmark, bits):
    func = getattr(Func, f"blake2b_{bits}")
    benchmark(sum, BENCH_DATA, func)


def test_bench_encode(benchmark):
    mh = sum(BENCH_DATA, Func.sha2_256)
    benchmark(mh.encode)


def test_bench_decode(benchmark):
    encoded = sum(BENCH_DATA, Func.sha2_256).encode()
    benchmark(decode, encoded)
