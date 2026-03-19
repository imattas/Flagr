"""
Substitution cipher solver using frequency analysis.

This unit maps character frequencies in the target text to standard
English letter frequencies (ETAOINSHRDLU...) to attempt decryption
of simple monoalphabetic substitution ciphers.

You can read more about frequency analysis here:
https://en.wikipedia.org/wiki/Frequency_analysis
"""

import io
import string
from collections import Counter
from typing import Any, Generator

from flagr.unit import NotApplicable, NotEnglishAndPrintableUnit
from flagr.units.crypto import CryptoUnit


# English letter frequency order (most common to least common)
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


class Unit(NotEnglishAndPrintableUnit, CryptoUnit):

    GROUPS = ["crypto", "substitution"]
    """
    Tags for this unit: crypto category and substitution cipher name.
    """

    BLOCKED_GROUPS = ["crypto"]
    """
    Do not recurse into other crypto units.
    """

    PRIORITY = 70
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. This unit has a lower priority because frequency
    analysis is a heuristic approach and may produce false positives.
    """

    RECURSE_SELF = False
    """
    Do not recurse into self.
    """

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        # Read target data
        try:
            self.raw_text = self.target.raw.decode("utf-8", errors="ignore")
        except Exception:
            raise NotApplicable("could not decode target as text")

        # Count only alphabetic characters
        alpha_chars = [c.upper() for c in self.raw_text if c.isalpha()]
        if len(alpha_chars) < 10:
            raise NotApplicable("not enough alphabetic characters for frequency analysis")

        # Build frequency-ordered list from the ciphertext
        freq = Counter(alpha_chars)
        self._cipher_freq_order = "".join(
            [ch for ch, _ in freq.most_common()]
        )

        # Pad with remaining letters not seen in the text
        for ch in string.ascii_uppercase:
            if ch not in self._cipher_freq_order:
                self._cipher_freq_order += ch

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield the frequency-based mapping as a single case.
        """
        yield None

    def evaluate(self, case: Any) -> None:
        """
        Apply the frequency analysis substitution and register the result.

        :param case: Not used.
        :return: None.
        """
        # Build the substitution mapping: cipher letter -> English letter
        mapping = {}
        for i, cipher_char in enumerate(self._cipher_freq_order):
            if i < len(ENGLISH_FREQ_ORDER):
                mapping[cipher_char] = ENGLISH_FREQ_ORDER[i]

        # Apply the mapping to the original text
        result = []
        for c in self.raw_text:
            upper = c.upper()
            if upper in mapping:
                # Preserve original case
                mapped = mapping[upper]
                if c.islower():
                    result.append(mapped.lower())
                else:
                    result.append(mapped)
            else:
                result.append(c)

        result = "".join(result)

        self.manager.register_data(self, result)
