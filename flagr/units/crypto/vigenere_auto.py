"""
Automatic Vigenere cipher solver using Kasiski examination.

This unit attempts to automatically break Vigenere ciphers by:
1. Using Kasiski examination to determine key length
2. Using frequency analysis on each position to find the key

Extends the existing vigenere unit which requires a known key.
"""

import string
from typing import Any, Generator
from math import gcd
from functools import reduce

import regex as re
from flagr.unit import NotEnglishAndPrintableUnit, NotApplicable
from flagr.units.crypto import CryptoUnit

ENGLISH_FREQ = [
    0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202,
    0.0609, 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675,
    0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906, 0.0276,
    0.0098, 0.0236, 0.0015, 0.0197, 0.0007
]


class Unit(NotEnglishAndPrintableUnit, CryptoUnit):

    GROUPS = ["crypto", "vigenere", "vigenere_auto"]
    PRIORITY = 60
    RECURSE_SELF = False
    BLOCKED_GROUPS = ["crypto"]

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw
        if isinstance(data, str):
            pass
        else:
            data = bytes(data).decode("utf-8", errors="replace")

        # Only apply to mostly alphabetic text of reasonable length
        alpha = "".join(c for c in data if c.isalpha())
        if len(alpha) < 30:
            raise NotApplicable("not enough alphabetic characters")

    def _kasiski_key_lengths(self, text, max_len=20):
        """Use Kasiski examination to find likely key lengths."""
        text = text.upper()
        distances = []

        # Find repeated trigrams
        for i in range(len(text) - 2):
            trigram = text[i:i+3]
            for j in range(i + 3, len(text) - 2):
                if text[j:j+3] == trigram:
                    distances.append(j - i)

        if not distances:
            return list(range(2, min(max_len + 1, 8)))

        # Find GCD of distances
        gcds = {}
        for d in distances:
            for kl in range(2, max_len + 1):
                if d % kl == 0:
                    gcds[kl] = gcds.get(kl, 0) + 1

        # Sort by frequency
        sorted_lengths = sorted(gcds.items(), key=lambda x: x[1], reverse=True)
        return [kl for kl, _ in sorted_lengths[:5]]

    def _score_text(self, text):
        """Score how English-like text is based on letter frequency."""
        text = text.upper()
        freq = [0] * 26
        total = 0
        for c in text:
            if c.isalpha():
                freq[ord(c) - ord('A')] += 1
                total += 1
        if total == 0:
            return 0

        score = 0
        for i in range(26):
            observed = freq[i] / total
            score += abs(observed - ENGLISH_FREQ[i])
        return -score  # Higher is better (less deviation)

    def _crack_single_column(self, column):
        """Find best shift for a single Vigenere column."""
        best_shift = 0
        best_score = float('-inf')

        for shift in range(26):
            decrypted = ""
            for c in column:
                if c.isalpha():
                    base = ord('A') if c.isupper() else ord('a')
                    decrypted += chr((ord(c.upper()) - ord('A') - shift) % 26 + base)
                else:
                    decrypted += c
            score = self._score_text(decrypted)
            if score > best_score:
                best_score = score
                best_shift = shift

        return best_shift

    def enumerate(self) -> Generator[Any, None, None]:
        """Try different key lengths from Kasiski analysis."""
        data = self.target.raw
        if isinstance(data, str):
            pass
        else:
            data = bytes(data).decode("utf-8", errors="replace")
        alpha = "".join(c for c in data if c.isalpha())

        key_lengths = self._kasiski_key_lengths(alpha)
        for kl in key_lengths:
            yield kl

    def evaluate(self, case: Any):
        """Attempt to crack Vigenere with the given key length."""
        key_length = case
        data = self.target.raw
        if isinstance(data, str):
            pass
        else:
            data = bytes(data).decode("utf-8", errors="replace")

        # Extract only alphabetic characters for analysis
        alpha_indices = [(i, c) for i, c in enumerate(data) if c.isalpha()]
        alpha_only = "".join(c for _, c in alpha_indices)

        # Split into columns by key position
        columns = [""] * key_length
        for i, c in enumerate(alpha_only):
            columns[i % key_length] += c

        # Find best shift for each column
        key = ""
        for col in columns:
            shift = self._crack_single_column(col)
            key += chr(shift + ord('A'))

        # Decrypt the full text
        result = list(data)
        key_idx = 0
        for i, c in enumerate(data):
            if c.isalpha():
                shift = ord(key[key_idx % key_length]) - ord('A')
                base = ord('A') if c.isupper() else ord('a')
                result[i] = chr((ord(c) - base - shift) % 26 + base)
                key_idx += 1

        plaintext = "".join(result)

        report = f"Vigenere Auto-Solve (key length {key_length}):\n"
        report += f"  Key: {key}\n"
        report += f"  Plaintext: {plaintext[:200]}"

        self.manager.register_data(self, report)
        self.manager.register_data(self, plaintext)
