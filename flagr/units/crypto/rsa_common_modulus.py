"""
RSA Common Modulus Attack.

This unit detects two ciphertexts encrypted with the same modulus n but
different public exponents e1 and e2. Using the extended GCD algorithm,
the plaintext can be recovered without factoring n.

This attack works when gcd(e1, e2) = 1, which allows computing
m = c1^s1 * c2^s2 mod n where s1*e1 + s2*e2 = 1.
"""

from typing import Any, Generator

import regex as re

from flagr.unit import NotApplicable, PrintableDataUnit
from flagr.units.crypto import CryptoUnit


# Patterns to extract RSA parameters (allow multiple e and c values)
N_PATTERN = re.compile(rb"[nN]\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")
E_PATTERN = re.compile(rb"[eE]\d?\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")
C_PATTERN = re.compile(rb"[cC]\d?\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")


def _parse_int(s):
    """Parse an integer from a byte string, handling hex and decimal."""
    s = s.strip()
    if s.endswith(b"L"):
        s = s[:-1]
    try:
        if s.startswith(b"0x") or s.startswith(b"0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return None


def _egcd(a, b):
    """
    Extended Euclidean algorithm.

    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _long_to_bytes(n):
    """Convert a positive integer to a bytes object."""
    if n == 0:
        return b"\x00"
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder="big")


def _common_modulus_attack(n, e1, e2, c1, c2):
    """
    Perform the common modulus attack.

    Given n, (e1, c1), (e2, c2) where gcd(e1, e2) = 1,
    recover plaintext m = c1^s1 * c2^s2 mod n.

    Returns the plaintext integer, or None on failure.
    """
    g, s1, s2 = _egcd(e1, e2)
    if g != 1:
        return None

    # Handle negative exponents by using modular inverse
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m


class Unit(PrintableDataUnit, CryptoUnit):

    GROUPS = ["crypto", "rsa", "rsa_common_modulus"]
    """
    Tags for this unit: crypto category, rsa family, and specific unit name.
    """

    BLOCKED_GROUPS = ["crypto"]
    """
    Do not recurse into other crypto units.
    """

    PRIORITY = 40
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default.
    """

    RECURSE_SELF = False
    """
    Do not recurse into self.
    """

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw

        # We need exactly one n, and at least two e and c values
        n_match = N_PATTERN.search(data)
        e_matches = E_PATTERN.findall(data)
        c_matches = C_PATTERN.findall(data)

        if not n_match:
            raise NotApplicable("no modulus (n) found")

        self._n = _parse_int(n_match.group(1))
        if self._n is None:
            raise NotApplicable("could not parse modulus")

        # Parse all e and c values
        self._e_values = []
        for em in e_matches:
            val = _parse_int(em)
            if val is not None:
                self._e_values.append(val)

        self._c_values = []
        for cm in c_matches:
            val = _parse_int(cm)
            if val is not None:
                self._c_values.append(val)

        if len(self._e_values) < 2:
            raise NotApplicable("need at least two different exponents (e)")
        if len(self._c_values) < 2:
            raise NotApplicable("need at least two different ciphertexts (c)")

        # Ensure we have distinct e values
        if self._e_values[0] == self._e_values[1]:
            raise NotApplicable("exponents are not distinct")

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield pairs of (e, c) combinations to try.
        """
        # Try all pairs of (e_i, c_i) with (e_j, c_j)
        count = min(len(self._e_values), len(self._c_values))
        for i in range(count):
            for j in range(i + 1, count):
                yield (i, j)

    def evaluate(self, case: Any) -> None:
        """
        Attempt the common modulus attack on the given pair.

        :param case: A tuple (i, j) indexing into e_values and c_values.
        :return: None.
        """
        i, j = case

        try:
            e1 = self._e_values[i]
            e2 = self._e_values[j]
            c1 = self._c_values[i]
            c2 = self._c_values[j]

            m = _common_modulus_attack(self._n, e1, e2, c1, c2)
            if m is None or m <= 0:
                return

            plaintext = _long_to_bytes(m)

            try:
                result = plaintext.decode("utf-8", errors="replace")
            except Exception:
                result = plaintext

            self.manager.register_data(self, result)

        except (ValueError, ZeroDivisionError, OverflowError):
            pass
