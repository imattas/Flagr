"""
Unicode escape sequence decoder.

This unit detects and decodes Unicode escape sequences commonly found
in CTF challenges, including:
- Python unicode escapes: \\u0066\\u006c\\u0061\\u0067
- HTML entities: &#102;&#108;&#97;&#103;
- JavaScript escapes: \\x66\\x6c\\x61\\x67
"""

from typing import Any
import regex as re
import html

from flagr.unit import RegexUnit
import flagr.util


class Unit(RegexUnit):

    GROUPS = ["raw", "decode", "unicode"]
    PRIORITY = 30
    RECURSE_SELF = False

    # Match sequences of unicode escapes
    PATTERN = re.compile(
        rb"(\\u[0-9a-fA-F]{4}){3,}"       # \u0066\u006c...
        rb"|(&#[0-9]{1,5};){3,}"            # &#102;&#108;...
        rb"|(&#x[0-9a-fA-F]{1,4};){3,}"     # &#x66;&#x6c;...
        rb"|(\\x[0-9a-fA-F]{2}){3,}",       # \x66\x6c...
        re.MULTILINE | re.DOTALL,
    )

    def evaluate(self, match):
        """
        Decode unicode escape sequences.
        """
        data = match.group()

        try:
            text = data.decode("utf-8", errors="replace")
            result = None

            if "\\u" in text:
                # Python unicode escapes
                result = text.encode("utf-8").decode("unicode_escape")
            elif "&#x" in text:
                # HTML hex entities
                result = html.unescape(text)
            elif "&#" in text:
                # HTML decimal entities
                result = html.unescape(text)
            elif "\\x" in text:
                # Hex escapes
                result = bytes.fromhex(
                    text.replace("\\x", "")
                ).decode("utf-8", errors="replace")

            if result and len(result) > 0:
                if flagr.util.isprintable(result.encode() if isinstance(result, str) else result):
                    self.manager.register_data(self, result)

        except (UnicodeDecodeError, ValueError):
            pass
