"""
RSA Wiener's Attack for small private exponent.

This unit detects RSA parameters (n, e, c) from target text using regex
and applies continued fractions to recover a small private exponent d.
When e is disproportionately large relative to n, the private exponent d
can be recovered using Wiener's continued fraction method.

You can read more about Wiener's attack here:
https://en.wikipedia.org/wiki/Wiener%27s_attack
"""

from typing import Any, Generator

import regex as re

from flagr.unit import NotApplicable, PrintableDataUnit
from flagr.units.crypto import CryptoUnit


# Patterns to extract RSA parameters from target text
N_PATTERN = re.compile(rb"[nN]\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")
E_PATTERN = re.compile(rb"[eE]\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")
C_PATTERN = re.compile(rb"[cC]\s*[=:]\s*(0?[xX]?[0-9a-fA-F]+)")


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


def _isqrt(n):
    """Integer square root."""
    if n < 0:
        return None
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def _rational_to_contfrac(x, y):
    """Convert rational x/y to a list of continued fraction coefficients."""
    a = x // y
    coeffs = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        coeffs.append(a)
    return coeffs


def _convergents_from_contfrac(coeffs):
    """Compute convergents (k, d) from continued fraction coefficients."""
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    convergents = []
    for c in coeffs:
        h_prev, h_curr = h_curr, c * h_curr + h_prev
        k_prev, k_curr = k_curr, c * k_curr + k_prev
        convergents.append((h_curr, k_curr))
    return convergents


def _wiener_attack(e, n):
    """
    Attempt Wiener's attack to recover d from (e, n).

    Returns d if successful, None otherwise.
    """
    coeffs = _rational_to_contfrac(e, n)
    convergents = _convergents_from_contfrac(coeffs)

    for k, d in convergents:
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        # n = p * q and phi = (p-1)(q-1) = n - p - q + 1
        # So p + q = n - phi + 1
        s = n - phi + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sq = _isqrt(discriminant)
        if sq is None or sq * sq != discriminant:
            continue

        if (s + sq) % 2 == 0:
            return d

    return None


def _long_to_bytes(n):
    """Convert a positive integer to a bytes object."""
    if n == 0:
        return b"\x00"
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder="big")


class Unit(PrintableDataUnit, CryptoUnit):

    GROUPS = ["crypto", "rsa", "rsa_wiener"]
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
    lowest priority. 50 is the default. This unit has a higher priority
    since Wiener's attack is a common CTF technique.
    """

    RECURSE_SELF = False
    """
    Do not recurse into self.
    """

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw

        # Extract RSA parameters
        n_match = N_PATTERN.search(data)
        e_match = E_PATTERN.search(data)
        c_match = C_PATTERN.search(data)

        if not n_match:
            raise NotApplicable("no modulus (n) found")
        if not e_match:
            raise NotApplicable("no exponent (e) found")
        if not c_match:
            raise NotApplicable("no ciphertext (c) found")

        self._n = _parse_int(n_match.group(1))
        self._e = _parse_int(e_match.group(1))
        self._c = _parse_int(c_match.group(1))

        if self._n is None or self._e is None or self._c is None:
            raise NotApplicable("could not parse RSA parameters")

        # Wiener's attack is only useful when e is large relative to n
        if self._e <= 0x10001:
            raise NotApplicable("e is not large enough for Wiener's attack")

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield a single case for evaluation.
        """
        yield None

    def evaluate(self, case: Any) -> None:
        """
        Attempt Wiener's attack on the RSA parameters.

        :param case: Not used.
        :return: None.
        """
        try:
            d = _wiener_attack(self._e, self._n)
            if d is None:
                return

            # Decrypt the ciphertext
            m = pow(self._c, d, self._n)
            plaintext = _long_to_bytes(m)

            try:
                result = plaintext.decode("utf-8", errors="replace")
            except Exception:
                result = plaintext

            self.manager.register_data(self, result)

        except (ValueError, ZeroDivisionError, OverflowError):
            pass
