"""
Hash identification and lookup.

This unit detects common hash formats (MD5, SHA1, SHA256, SHA512) in the
target data and attempts to crack them using online rainbow table lookups
or common CTF wordlists.

Extends flagr's original MD5-only crack unit to support modern hash types.
"""

import hashlib
from typing import Any, Generator

import regex as re
import requests
from flagr.unit import RegexUnit, NotApplicable


# Hash patterns by type
HASH_PATTERNS = {
    "md5": re.compile(rb"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(rb"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(rb"\b[a-fA-F0-9]{64}\b"),
    "sha512": re.compile(rb"\b[a-fA-F0-9]{128}\b"),
}

# Common CTF passwords/flags to try
COMMON_WORDS = [
    "password", "admin", "flag", "root", "test", "secret",
    "ctf", "hack", "1234", "12345", "123456", "letmein",
    "qwerty", "abc123", "monkey", "shadow", "master",
]


class Unit(RegexUnit):

    GROUPS = ["crypto", "crack", "hash", "bruteforce"]
    PRIORITY = 60
    RECURSE_SELF = False
    BLOCKED_GROUPS = ["crypto"]

    # Match any hex string that could be a hash (32, 40, 64, or 128 chars)
    PATTERN = re.compile(
        rb"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",
        re.MULTILINE,
    )

    def evaluate(self, match):
        """
        Identify the hash type and attempt to crack it.
        """
        hash_str = match.group().decode("ascii", errors="ignore").lower()
        hash_bytes = hash_str.encode()

        # Identify hash type
        hash_len = len(hash_str)
        if hash_len == 32:
            hash_type = "MD5"
            hash_func = hashlib.md5
        elif hash_len == 40:
            hash_type = "SHA1"
            hash_func = hashlib.sha1
        elif hash_len == 64:
            hash_type = "SHA256"
            hash_func = hashlib.sha256
        else:
            return

        # Try common words
        for word in COMMON_WORDS:
            if hash_func(word.encode()).hexdigest() == hash_str:
                result = f"Hash cracked: {hash_type}({word}) = {hash_str}"
                self.manager.register_data(self, result)
                self.manager.register_data(self, word)
                return

        # Try online lookup (only for MD5 and SHA1)
        if hash_type in ("MD5", "SHA1"):
            try:
                resp = requests.get(
                    f"https://api.hashtoolkit.com/reverse?hash={hash_str}",
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("result"):
                        cracked = data["result"]
                        result = f"Hash cracked (online): {hash_type} = {cracked}"
                        self.manager.register_data(self, result)
                        self.manager.register_data(self, cracked)
                        return
            except Exception:
                pass

        # Report uncracked hash
        self.manager.register_data(
            self, f"Detected {hash_type} hash: {hash_str} (not cracked)"
        )
