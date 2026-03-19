"""
Blockchain / smart contract CTF helper.

This unit detects Ethereum-style addresses, transaction hashes,
and Solidity contract patterns in the target data. It extracts
relevant information for blockchain CTF challenges.
"""

from typing import Any

import regex as re
from flagr.unit import RegexUnit


class Unit(RegexUnit):

    GROUPS = ["misc", "blockchain", "ethereum", "crypto"]
    PRIORITY = 50
    RECURSE_SELF = False
    NO_RECURSE = True

    # Match Ethereum addresses, tx hashes, or Solidity keywords
    PATTERN = re.compile(
        rb"0x[0-9a-fA-F]{40}"           # ETH address
        rb"|0x[0-9a-fA-F]{64}"          # TX hash / storage slot
        rb"|(?:pragma solidity|contract\s+\w+|function\s+\w+.*public)",  # Solidity
        re.MULTILINE | re.DOTALL,
    )

    def evaluate(self, match):
        """Analyze blockchain-related content."""
        data = match.group()

        try:
            text = data.decode("utf-8", errors="replace")

            if text.startswith("0x") and len(text) == 42:
                result = f"Ethereum Address Detected: {text}\n  Checksum valid: {self._is_checksum_address(text)}"
                self.manager.register_data(self, result)
            elif text.startswith("0x") and len(text) == 66:
                result = f"Transaction/Storage Hash: {text}"
                self.manager.register_data(self, result)
            elif "pragma solidity" in text or "contract " in text:
                self.manager.register_data(
                    self, f"Solidity Contract Detected:\n  {text[:200]}"
                )

        except Exception:
            pass

    @staticmethod
    def _is_checksum_address(addr):
        """Check if an Ethereum address passes EIP-55 checksum."""
        try:
            import hashlib
            addr_lower = addr[2:].lower()
            addr_hash = hashlib.sha3_256(addr_lower.encode()).hexdigest()
            for i, c in enumerate(addr_lower):
                if c.isalpha():
                    if int(addr_hash[i], 16) >= 8 and addr[i + 2].isupper():
                        continue
                    elif int(addr_hash[i], 16) < 8 and addr[i + 2].islower():
                        continue
                    else:
                        return False
            return True
        except Exception:
            return False
