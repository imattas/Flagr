"""
Buffer overflow detection and offset calculation.

This unit detects buffer overflow vulnerabilities in ELF binaries by
crashing the binary with a cyclic pattern and analyzing the resulting
core file to determine the exact offset to the return address.

Ported from autorop's Corefile analysis.
"""

import os
import stat
import subprocess
from typing import Any

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "overflow", "bof"]
    PRIORITY = 25
    RECURSE_SELF = False

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        try:
            from pwn import ELF
            self._elf = ELF(self.target.path, checksec=False)
        except Exception:
            raise NotApplicable("could not parse ELF")

        # Skip PIE binaries (harder to exploit automatically)
        if self._elf.pie:
            raise NotApplicable("PIE binary - not suitable for simple overflow")

    def evaluate(self, case: Any):
        """
        Crash the binary with a cyclic pattern and analyze the corefile
        to find the buffer overflow offset.
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import process, cyclic, cyclic_find, context, Coredump

        context.binary = self._elf
        context.log_level = "error"

        # Make binary executable
        st = os.stat(self.target.path)
        os.chmod(self.target.path, st.st_mode | stat.S_IEXEC)

        try:
            # Use absolute path for binary
            binary_path = os.path.realpath(self.target.path)

            # Crash with cyclic pattern
            p = process(binary_path)
            pattern = cyclic(1024, n=context.bytes)
            p.sendline(pattern)
            p.wait(timeout=5)

            # Find the corefile
            corefile = p.corefile
            if corefile is None:
                p.close()
                return

            fault_addr = corefile.fault_addr
            offset = cyclic_find(fault_addr, n=context.bytes)
            p.close()

            if offset and offset > 0 and offset < 10000:
                result = (
                    f"Buffer Overflow Detected!\n"
                    f"  Binary: {binary_path}\n"
                    f"  Architecture: {self._elf.arch} ({self._elf.bits}-bit)\n"
                    f"  Offset to return address: {offset} bytes\n"
                    f"  PIE: {'Yes' if self._elf.pie else 'No'}\n"
                    f"  NX: {'Yes' if self._elf.nx else 'No'}\n"
                    f"  Canary: {'Yes' if self._elf.canary else 'No'}\n"
                    f"  RELRO: {'Full' if getattr(self._elf, 'full_relro', False) else 'Partial' if getattr(self._elf, 'relro', False) else 'None'}"
                )
                self.manager.register_data(self, result)

        except Exception as e:
            # Log the error for debugging
            try:
                self.manager.register_data(self, f"Overflow detection error: {e}")
            except Exception:
                pass
