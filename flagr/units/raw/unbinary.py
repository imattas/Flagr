"""
Decode data represented as binary values.

This unit will return the data represented in both little-endian notation
and in big-endian notation.
"""

from typing import List
import regex as re

from flagr.unit import RegexUnit


class Unit(RegexUnit):

    PRIORITY = 50
    """
    Priority works with 0 being the highest priority, and 100 being the 
    lowest priority. 50 is the default priorty. This unit has the default
    priority.
    """

    GROUPS = ["raw", "decode"]
    """
    These are "tags" for a unit. Considering it is a Raw unit, "raw"
    is included, as well as the tag "decode", and the name of the unit itself,
    "unbinary".
    """

    PATTERN = re.compile(rb"(([01]{7,8}( ([01]{7,8})){3,}|[01]{32,}))")
    """
    The pattern to match for binary data.
    """

    def evaluate(self, match):
        """
        Evaluate the target. Convert the binary data found within the target
        and recurse on any new found information.

        :param match: A match returned by the ``RegexUnit``.

        :return: None. This function should not return any data.
        """

        raw = match.group()

        # If the data has spaces, split on spaces
        if b" " in raw:
            chunks: List[bytes] = raw.split(b" ")
        else:
            # No spaces - try splitting into 8-bit and 7-bit chunks
            for bit_width in (8, 7):
                if len(raw) % bit_width == 0:
                    chunks = [raw[i:i+bit_width] for i in range(0, len(raw), bit_width)]
                    result = b""
                    for m in chunks:
                        try:
                            result += int(m, 2).to_bytes(1, byteorder="big")
                        except (ValueError, OverflowError):
                            break
                    else:
                        self.manager.register_data(self, result)
            return

        result = b""

        # Convert all the bits into bytes (little endian)
        for m in chunks:
            result += int(m, 2).to_bytes((len(m) + 7) // 8, byteorder="little")

        # Register data
        self.manager.register_data(self, result)

        result = b""
        for m in chunks:
            result += int(m, 2).to_bytes((len(m) + 7) // 8, byteorder="big")

        # Register data
        self.manager.register_data(self, result)
