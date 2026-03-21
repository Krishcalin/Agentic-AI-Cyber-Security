"""Lightweight bloom filter implementation for package verification.

Uses MurmurHash-style hashing for fast approximate membership testing.
No external dependencies — pure Python implementation.
"""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path


class BloomFilter:
    """Space-efficient probabilistic set membership test.

    Args:
        expected_items: Expected number of items to store.
        false_positive_rate: Desired false positive rate (0.0 to 1.0).
    """

    def __init__(self, expected_items: int = 100_000, false_positive_rate: float = 0.001) -> None:
        self.expected_items = expected_items
        self.fp_rate = false_positive_rate

        # Calculate optimal size and hash count
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)
        self.bit_array = bytearray(math.ceil(self.size / 8))
        self.count = 0

    def add(self, item: str) -> None:
        """Add an item to the filter."""
        for i in range(self.hash_count):
            idx = self._hash(item, i) % self.size
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self.count += 1

    def __contains__(self, item: str) -> bool:
        """Check if item is possibly in the set (may false-positive)."""
        for i in range(self.hash_count):
            idx = self._hash(item, i) % self.size
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def add_many(self, items: list[str]) -> None:
        """Add multiple items at once."""
        for item in items:
            self.add(item)

    def save(self, path: str) -> None:
        """Save bloom filter to a binary file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            # Header: size(8), hash_count(4), count(8)
            f.write(struct.pack("<QIQ", self.size, self.hash_count, self.count))
            f.write(self.bit_array)

    @classmethod
    def load(cls, path: str) -> BloomFilter:
        """Load bloom filter from a binary file."""
        with open(path, "rb") as f:
            header = f.read(20)
            size, hash_count, count = struct.unpack("<QIQ", header)
            bit_array = bytearray(f.read())

        bf = cls.__new__(cls)
        bf.size = size
        bf.hash_count = hash_count
        bf.count = count
        bf.bit_array = bit_array
        bf.expected_items = count
        bf.fp_rate = 0.001
        return bf

    def _hash(self, item: str, seed: int) -> int:
        """Generate a hash for an item with a given seed."""
        data = f"{seed}:{item}".encode("utf-8")
        h = hashlib.md5(data).digest()
        return struct.unpack("<Q", h[:8])[0]

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """Calculate optimal bit array size."""
        return int(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """Calculate optimal number of hash functions."""
        return max(1, int((m / n) * math.log(2)))

    def __len__(self) -> int:
        return self.count

    def __repr__(self) -> str:
        return f"BloomFilter(items={self.count}, size={self.size}, hashes={self.hash_count})"
