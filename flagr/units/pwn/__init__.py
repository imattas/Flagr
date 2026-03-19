"""
Pwn (binary exploitation) units for flagr.

These units detect ELF binary targets and attempt automated exploitation
using techniques ported from autorop: buffer overflow detection, ret2win,
ret2libc, and ROP chain analysis.

Requires pwntools to be installed.
"""

from flagr.unit import NotApplicable
from flagr.unit import FileUnit


class PwnUnit(FileUnit):
    """
    Base class for pwn units. Ensures the target is an ELF binary
    and that pwntools is available.
    """

    def __init__(self, *args, **kwargs):
        super(PwnUnit, self).__init__(*args, **kwargs, keywords=["ELF"])

        try:
            import pwn
        except ImportError:
            raise NotApplicable("pwntools not installed")
