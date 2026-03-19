"""
Bacon cipher decoder.

This unit detects patterns of 'a'/'b' characters (or binary-like 5-character
groups) and decodes them using Francis Bacon's biliteral cipher.

In Bacon's cipher, each letter is encoded as a 5-character sequence of 'a'
and 'b' values (or equivalently, 0 and 1).

You can read more about Bacon's cipher here:
https://en.wikipedia.org/wiki/Bacon%27s_cipher
"""

from typing import Any, Generator

import regex as re

from flagr.unit import NotApplicable, PrintableDataUnit
from flagr.units.crypto import CryptoUnit


# Bacon's cipher alphabet (I/J and U/V share codes)
BACON_ALPHABET = {
    "aaaaa": "A",
    "aaaab": "B",
    "aaaba": "C",
    "aaabb": "D",
    "aabaa": "E",
    "aabab": "F",
    "aabba": "G",
    "aabbb": "H",
    "abaaa": "I",  # I/J
    "abaab": "J",  # Alternative: some use abaaa for both I/J
    "ababa": "K",
    "ababb": "L",
    "abbaa": "M",
    "abbab": "N",
    "abbba": "O",
    "abbbb": "P",
    "baaaa": "Q",
    "baaab": "R",
    "baaba": "S",
    "baabb": "T",
    "babaa": "U",  # U/V
    "babab": "V",  # Alternative: some use babaa for both U/V
    "babba": "W",
    "babbb": "X",
    "baaaa": "Q",
    "baaab": "R",
    "baaba": "S",
    "baabb": "T",
    "babaa": "U",
    "babab": "V",
    "babba": "W",
    "babbb": "X",
    "baaaa": "Q",
    "baaba": "S",
    "baaab": "R",
    "baabb": "T",
    "babaa": "U",
    "babab": "V",
    "babba": "W",
    "babbb": "X",
    "baaaa": "Q",
    "baaab": "R",
    "baaba": "S",
    "baabb": "T",
    "babaa": "U",
    "babab": "V",
    "babba": "W",
    "babbb": "X",
    "baaaa": "Q",
}

# Build a clean lookup from 5-bit index to letter (26-letter variant)
BACON_TABLE = {}
_letters_26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for _i, _letter in enumerate(_letters_26):
    _code = ""
    for _bit in range(4, -1, -1):
        _code += "b" if (_i >> _bit) & 1 else "a"
    BACON_TABLE[_code] = _letter

# Also build the 24-letter (I=J, U=V) variant
BACON_TABLE_24 = {}
_letters_24 = "ABCDEFGHIKLMNOPQRSTUWXYZ"
for _i, _letter in enumerate(_letters_24):
    _code = ""
    for _bit in range(4, -1, -1):
        _code += "b" if (_i >> _bit) & 1 else "a"
    BACON_TABLE_24[_code] = _letter

# Pattern: sequences of a/b or A/B characters (at least 5)
BACON_PATTERN = re.compile(rb"[aAbB]{5,}", re.IGNORECASE)
# Pattern: sequences of 0/1 characters (at least 5)
BINARY_PATTERN = re.compile(rb"[01]{5,}")


def _decode_bacon(text, table):
    """
    Decode a string of a/b characters using the given Bacon table.

    Returns the decoded string or None if decoding fails.
    """
    text = text.lower()
    result = []
    for i in range(0, len(text) - 4, 5):
        chunk = text[i : i + 5]
        if chunk in table:
            result.append(table[chunk])
        else:
            return None
    return "".join(result) if result else None


class Unit(PrintableDataUnit, CryptoUnit):

    GROUPS = ["crypto", "bacon"]
    """
    Tags for this unit: crypto category and bacon cipher name.
    """

    BLOCKED_GROUPS = ["crypto"]
    """
    Do not recurse into other crypto units.
    """

    PRIORITY = 60
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority.
    """

    RECURSE_SELF = False
    """
    Do not recurse into self.
    """

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw

        # Look for a/b patterns or binary patterns
        self._ab_matches = BACON_PATTERN.findall(data)
        self._bin_matches = BINARY_PATTERN.findall(data)

        if not self._ab_matches and not self._bin_matches:
            raise NotApplicable("no Bacon cipher patterns found")

        # Filter to only groups whose length is a multiple of 5
        self._ab_matches = [
            m for m in self._ab_matches if len(m) % 5 == 0 and len(m) >= 5
        ]
        self._bin_matches = [
            m for m in self._bin_matches if len(m) % 5 == 0 and len(m) >= 5
        ]

        if not self._ab_matches and not self._bin_matches:
            raise NotApplicable("no valid Bacon cipher groups found")

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield decoding cases: each match with each table variant.
        """
        for match in self._ab_matches:
            yield ("ab", match, "26")
            yield ("ab", match, "24")
        for match in self._bin_matches:
            yield ("bin", match, "26")
            yield ("bin", match, "24")

    def evaluate(self, case: Any) -> None:
        """
        Attempt to decode a Bacon cipher match.

        :param case: A tuple of (mode, match_bytes, table_variant).
        :return: None.
        """
        mode, match_bytes, variant = case
        table = BACON_TABLE if variant == "26" else BACON_TABLE_24

        try:
            text = match_bytes.decode("ascii")

            if mode == "bin":
                # Convert 0/1 to a/b
                text = text.replace("0", "a").replace("1", "b")

            result = _decode_bacon(text, table)
            if result and len(result) > 0:
                self.manager.register_data(self, result)

        except (ValueError, UnicodeDecodeError):
            pass
