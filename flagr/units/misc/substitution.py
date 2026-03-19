"""
Substitution cipher solver.

This unit detects text that appears to be a monoalphabetic substitution
cipher and attempts to solve it using frequency analysis and dictionary
matching.

Common in classical crypto CTF challenges.
"""

import string
from typing import Any

import regex as re
from flagr.unit import NotEnglishAndPrintableUnit, NotApplicable


# English letter frequency (most to least common)
ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


class Unit(NotEnglishAndPrintableUnit):

    GROUPS = ["crypto", "misc", "substitution", "frequency"]
    PRIORITY = 70
    RECURSE_SELF = False
    BLOCKED_GROUPS = ["crypto"]

    @classmethod
    def get_name(cls) -> str:
        return "freq_substitution"

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw
        if isinstance(data, str):
            pass
        else:
            data = bytes(data).decode("utf-8", errors="replace")

        # Only apply to mostly-alphabetic text
        alpha_count = sum(1 for c in data if c.isalpha())
        if alpha_count < 20:
            raise NotApplicable("not enough alphabetic characters")

        total = len(data.strip())
        if total == 0 or alpha_count / total < 0.6:
            raise NotApplicable("not mostly alphabetic")

    def evaluate(self, case: Any):
        """
        Attempt frequency analysis substitution cipher solving.
        """
        data = self.target.raw
        if isinstance(data, str):
            pass
        else:
            data = bytes(data).decode("utf-8", errors="replace")

        # Count letter frequencies
        freq = {}
        for c in data.lower():
            if c.isalpha():
                freq[c] = freq.get(c, 0) + 1

        # Sort by frequency (most common first)
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        cipher_freq = "".join(c for c, _ in sorted_freq)

        # Build substitution map based on frequency
        sub_map = {}
        for i, c in enumerate(cipher_freq):
            if i < len(ENGLISH_FREQ):
                sub_map[c] = ENGLISH_FREQ[i]
                sub_map[c.upper()] = ENGLISH_FREQ[i].upper()

        # Apply substitution
        result = []
        for c in data:
            if c in sub_map:
                result.append(sub_map[c])
            else:
                result.append(c)

        result = "".join(result)

        # Report frequency analysis
        report = f"Frequency Analysis Result:\n"
        report += f"  Cipher frequency: {cipher_freq}\n"
        report += f"  Mapped to:        {ENGLISH_FREQ[:len(cipher_freq)]}\n"
        report += f"  Decoded text: {result[:200]}"

        self.manager.register_data(self, report)
        self.manager.register_data(self, result)
