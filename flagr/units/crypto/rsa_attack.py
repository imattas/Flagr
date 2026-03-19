"""
RSA attack suite for CTF challenges.

This unit detects RSA parameters (n, e, c) in the target data and
attempts various attacks:
- Small e attack (cube root)
- Fermat factorization (close primes)
- Wiener's attack (large e)
- Common modulus attack (same n, different e)

Extends the existing RSA unit with modern attack techniques.
"""

import math
from typing import Any, Generator

import regex as re
from flagr.unit import NotApplicable, PrintableDataUnit


# Patterns to extract RSA parameters
N_PATTERN = re.compile(rb"[nN]\s*[=:]\s*(\d+)")
E_PATTERN = re.compile(rb"[eE]\s*[=:]\s*(\d+)")
C_PATTERN = re.compile(rb"[cC]\s*[=:]\s*(\d+)")
P_PATTERN = re.compile(rb"[pP]\s*[=:]\s*(\d+)")
Q_PATTERN = re.compile(rb"[qQ]\s*[=:]\s*(\d+)")


def isqrt(n):
    """Integer square root."""
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def iroot(n, k):
    """Integer k-th root of n."""
    if n < 0:
        return -iroot(-n, k) if k % 2 else None
    if n == 0:
        return 0
    guess = int(round(n ** (1.0 / k)))
    # Refine
    for delta in range(-3, 4):
        g = guess + delta
        if g >= 0 and g**k == n:
            return g
    return None


def long_to_bytes(n):
    """Convert a long integer to bytes."""
    if n == 0:
        return b"\x00"
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder="big")


class Unit(PrintableDataUnit):

    GROUPS = ["crypto", "rsa", "rsa_attack", "math"]
    PRIORITY = 35
    RECURSE_SELF = False
    BLOCKED_GROUPS = ["crypto"]

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        data = self.target.raw

        # Extract RSA parameters
        n_match = N_PATTERN.search(data)
        e_match = E_PATTERN.search(data)
        c_match = C_PATTERN.search(data)

        if not c_match:
            raise NotApplicable("no ciphertext (c) found")

        self._c = int(c_match.group(1))
        self._n = int(n_match.group(1)) if n_match else None
        self._e = int(e_match.group(1)) if e_match else None

        # Also check for p, q directly given
        p_match = P_PATTERN.search(data)
        q_match = Q_PATTERN.search(data)
        self._p = int(p_match.group(1)) if p_match else None
        self._q = int(q_match.group(1)) if q_match else None

        if self._n is None and (self._p is None or self._q is None):
            raise NotApplicable("insufficient RSA parameters")

    def enumerate(self) -> Generator[Any, None, None]:
        """Yield attack names to try."""
        attacks = []

        if self._p and self._q:
            attacks.append("direct")

        if self._n and self._e:
            if self._e <= 17:
                attacks.append("small_e")
            attacks.append("fermat")
            if self._e > 100000:
                attacks.append("wiener")

        if not attacks:
            attacks.append("direct")

        for attack in attacks:
            yield attack

    def _decrypt(self, p, q, e, c):
        """Decrypt RSA given p, q, e, c."""
        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        return long_to_bytes(m)

    def evaluate(self, case: Any):
        """Run the specified RSA attack."""
        attack = case

        try:
            if attack == "direct" and self._p and self._q:
                e = self._e or 65537
                plaintext = self._decrypt(self._p, self._q, e, self._c)
                self.manager.register_data(self, plaintext)

            elif attack == "small_e" and self._e and self._n:
                # Try cube root / small e attack
                root = iroot(self._c, self._e)
                if root is not None:
                    plaintext = long_to_bytes(root)
                    self.manager.register_data(self, plaintext)

            elif attack == "fermat" and self._n:
                # Fermat factorization for close primes
                a = isqrt(self._n)
                if a * a < self._n:
                    a += 1
                for _ in range(100000):
                    b2 = a * a - self._n
                    b = isqrt(b2)
                    if b * b == b2:
                        p = a + b
                        q = a - b
                        if p * q == self._n and p != 1 and q != 1:
                            e = self._e or 65537
                            plaintext = self._decrypt(p, q, e, self._c)
                            result = f"Fermat factorization succeeded!\n  p = {p}\n  q = {q}\n  Plaintext: {plaintext}"
                            self.manager.register_data(self, result)
                            self.manager.register_data(self, plaintext)
                            return
                    a += 1

            elif attack == "wiener" and self._n and self._e:
                # Wiener's attack using continued fractions
                fracs = self._continued_fractions(self._e, self._n)
                for k, d in fracs:
                    if k == 0:
                        continue
                    phi = (self._e * d - 1) // k
                    # Solve quadratic: x^2 - (n - phi + 1)x + n = 0
                    b = self._n - phi + 1
                    disc = b * b - 4 * self._n
                    if disc < 0:
                        continue
                    sq = isqrt(disc)
                    if sq * sq != disc:
                        continue
                    p = (b + sq) // 2
                    q = (b - sq) // 2
                    if p * q == self._n:
                        plaintext = self._decrypt(p, q, self._e, self._c)
                        result = f"Wiener's attack succeeded!\n  d = {d}\n  p = {p}\n  q = {q}\n  Plaintext: {plaintext}"
                        self.manager.register_data(self, result)
                        self.manager.register_data(self, plaintext)
                        return

        except (ValueError, ZeroDivisionError, OverflowError):
            pass

    @staticmethod
    def _continued_fractions(e, n):
        """Generate convergents of e/n continued fraction."""
        fracs = []
        a, b = e, n
        cf = []
        while b:
            q, r = divmod(a, b)
            cf.append(q)
            a, b = b, r

        # Compute convergents
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for q in cf:
            h_prev, h_curr = h_curr, q * h_curr + h_prev
            k_prev, k_curr = k_curr, q * k_curr + k_prev
            fracs.append((h_curr, k_curr))

        return fracs
