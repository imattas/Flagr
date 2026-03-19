"""
JWT (JSON Web Token) decoder and analyzer.

This unit detects JWT tokens in the target data and decodes the header
and payload (which are simply base64url-encoded JSON). It also checks
for common JWT vulnerabilities like alg:none and weak secrets.

Common in modern web CTF challenges.
"""

import json
import base64
from typing import Any

import regex as re
from flagr.unit import RegexUnit, NotApplicable


def b64url_decode(data: bytes) -> bytes:
    """Decode base64url with padding fix."""
    if isinstance(data, str):
        data = data.encode()
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


class Unit(RegexUnit):

    GROUPS = ["crypto", "web", "jwt", "decode"]
    PRIORITY = 20
    RECURSE_SELF = False
    NO_RECURSE = True

    # JWT pattern: three base64url segments separated by dots
    PATTERN = re.compile(
        rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
        re.MULTILINE,
    )

    def evaluate(self, match):
        """
        Decode JWT header and payload, analyze for vulnerabilities.
        """
        token = match.group()
        parts = token.split(b".")

        if len(parts) < 2:
            return

        try:
            header_json = b64url_decode(parts[0])
            payload_json = b64url_decode(parts[1])

            header = json.loads(header_json)
            payload = json.loads(payload_json)

            lines = ["=== JWT Token Decoded ==="]
            lines.append(f"  Header: {json.dumps(header, indent=4)}")
            lines.append(f"  Payload: {json.dumps(payload, indent=4)}")

            # Check for vulnerabilities
            alg = header.get("alg", "").lower()
            if alg == "none":
                lines.append("  [VULN] Algorithm is 'none' - signature not verified!")
            elif alg == "hs256":
                lines.append("  [INFO] HMAC-SHA256 - try brute-forcing weak secret")
            elif alg.startswith("rs"):
                lines.append(f"  [INFO] RSA algorithm ({header.get('alg')})")

            # Check for interesting payload fields
            if "admin" in payload:
                lines.append(f"  [INTERESTING] admin field: {payload['admin']}")
            if "role" in payload:
                lines.append(f"  [INTERESTING] role field: {payload['role']}")
            if "flag" in str(payload).lower():
                lines.append("  [FLAG?] payload contains 'flag'")

            result = "\n".join(lines)
            self.manager.register_data(self, result)

            # Also register the raw payload for flag searching
            self.manager.register_data(self, json.dumps(payload))

        except (json.JSONDecodeError, Exception):
            pass
