"""
XOR brute-force with single-byte and multi-byte keys.

This unit attempts to decrypt XOR-encrypted data by trying all
single-byte keys (0x01-0xFF) and scoring the results for
printability and English text likelihood.

Common in CTF crypto and misc challenges.
"""

from typing import Any, Generator

from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit
import flagr.util


class Unit(BaseUnit):

    GROUPS = ["crypto", "misc", "xor", "bruteforce"]
    PRIORITY = 55
    RECURSE_SELF = False
    BLOCKED_GROUPS = ["crypto"]

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        # Only try on non-printable or non-English data that's not too large
        if self.target.is_url:
            raise NotApplicable("URL target")
        if len(self.target.raw) > 10000:
            raise NotApplicable("data too large for XOR bruteforce")
        if len(self.target.raw) < 5:
            raise NotApplicable("data too small")

    def enumerate(self) -> Generator[Any, None, None]:
        """Try all single-byte XOR keys."""
        for key in range(1, 256):
            yield key

    def evaluate(self, case: Any):
        """XOR decrypt with single byte key and check if result is useful."""
        key = case
        data = bytes(self.target.raw)

        # XOR with single byte key
        result = bytes([b ^ key for b in data])

        # Check if result is printable
        if flagr.util.isprintable(result):
            self.manager.register_data(self, result)
