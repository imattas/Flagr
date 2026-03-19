"""
Hill cipher brute force for 2x2 key matrix.

This unit tries all invertible 2x2 matrices mod 26 against the uppercase
target text to attempt decryption of a Hill cipher.

The Hill cipher encrypts pairs of letters using matrix multiplication mod 26.
For a 2x2 key matrix K, encryption is C = K * P mod 26. Decryption requires
finding K^{-1} mod 26 and computing P = K^{-1} * C mod 26.

You can read more about the Hill cipher here:
https://en.wikipedia.org/wiki/Hill_cipher
"""

import string
from typing import Any, Generator

from flagr.unit import NotApplicable, NotEnglishAndPrintableUnit
from flagr.units.crypto import CryptoUnit


def _mod_inverse(a, m):
    """
    Compute the modular inverse of a mod m using extended GCD.

    Returns the inverse, or None if it does not exist.
    """
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def _invert_2x2(matrix, mod=26):
    """
    Compute the inverse of a 2x2 matrix mod 26.

    Matrix is represented as (a, b, c, d) for [[a, b], [c, d]].
    Returns the inverse matrix tuple, or None if not invertible.
    """
    a, b, c, d = matrix
    det = (a * d - b * c) % mod
    det_inv = _mod_inverse(det, mod)
    if det_inv is None:
        return None

    # Inverse of [[a, b], [c, d]] is det_inv * [[d, -b], [-c, a]]
    inv_a = (det_inv * d) % mod
    inv_b = (det_inv * (-b)) % mod
    inv_c = (det_inv * (-c)) % mod
    inv_d = (det_inv * a) % mod
    return (inv_a, inv_b, inv_c, inv_d)


def _decrypt_hill(ciphertext, inv_key, mod=26):
    """
    Decrypt ciphertext (list of ints 0-25) using inverse key matrix.

    Returns decrypted text as a string of uppercase letters.
    """
    a, b, c, d = inv_key
    result = []
    for i in range(0, len(ciphertext) - 1, 2):
        x = ciphertext[i]
        y = ciphertext[i + 1]
        p1 = (a * x + b * y) % mod
        p2 = (c * x + d * y) % mod
        result.append(chr(p1 + ord("A")))
        result.append(chr(p2 + ord("A")))
    return "".join(result)


# Determinant values that are coprime with 26 (i.e., have a modular inverse)
_VALID_DETS = frozenset(d for d in range(26) if _mod_inverse(d, 26) is not None)


def _iter_invertible_matrices():
    """
    Lazily yield all invertible 2x2 inverse matrices mod 26.

    Instead of precomputing all 456,976 combinations at import time,
    this generator yields inverse matrices on demand during enumeration.
    """
    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a * d - b * c) % 26
                    if det in _VALID_DETS:
                        inv = _invert_2x2((a, b, c, d))
                        if inv is not None:
                            yield inv


class Unit(NotEnglishAndPrintableUnit, CryptoUnit):

    GROUPS = ["crypto", "hill"]
    """
    Tags for this unit: crypto category and hill cipher name.
    """

    BLOCKED_GROUPS = ["crypto"]
    """
    Do not recurse into other crypto units.
    """

    PRIORITY = 75
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. This unit has a low priority because brute-forcing
    all invertible 2x2 matrices is computationally expensive.
    """

    RECURSE_SELF = False
    """
    Do not recurse into self.
    """

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        # Read target data and extract uppercase alphabetic characters
        try:
            raw = self.target.raw.decode("utf-8", errors="ignore")
        except Exception:
            raise NotApplicable("could not decode target as text")

        self._alpha_only = "".join(c for c in raw.upper() if c in string.ascii_uppercase)

        if len(self._alpha_only) < 2:
            raise NotApplicable("not enough alphabetic characters for Hill cipher")

        # Ensure even length for 2x2 matrix decryption
        if len(self._alpha_only) % 2 != 0:
            self._alpha_only = self._alpha_only[:-1]

        # Convert to integer list (A=0, B=1, ..., Z=25)
        self._cipher_ints = [ord(c) - ord("A") for c in self._alpha_only]

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield each invertible 2x2 inverse matrix to try as a decryption key.
        """
        for inv_matrix in _iter_invertible_matrices():
            yield inv_matrix

    def evaluate(self, case: Any) -> None:
        """
        Attempt Hill cipher decryption with the given inverse key matrix.

        :param case: An inverse 2x2 key matrix tuple (a, b, c, d).
        :return: None.
        """
        try:
            result = _decrypt_hill(self._cipher_ints, case)
            self.manager.register_data(self, result)
        except (ValueError, ZeroDivisionError, IndexError):
            pass
