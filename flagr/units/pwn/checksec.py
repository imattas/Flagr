"""
Binary security analysis (checksec).

This unit analyzes ELF binaries for security features like NX, PIE,
stack canaries, RELRO, and reports potential vulnerabilities. This is
useful recon for CTF pwn challenges.
"""

import os
from typing import Any

from flagr.unit import NotApplicable
from flagr.units.pwn import PwnUnit


class Unit(PwnUnit):

    GROUPS = ["pwn", "elf", "checksec", "recon"]
    PRIORITY = 15
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        try:
            from pwn import ELF
            self._elf = ELF(self.target.path, checksec=False)
        except Exception:
            raise NotApplicable("could not parse ELF")

    def evaluate(self, case: Any):
        """
        Analyze the binary for security features and report findings.
        """
        elf = self._elf

        # Gather security info
        protections = []
        vulnerabilities = []

        # NX (No-Execute)
        nx = getattr(elf, 'nx', None)
        if nx:
            protections.append("NX enabled (no shellcode on stack)")
        else:
            vulnerabilities.append("NX disabled - stack is executable (shellcode possible)")

        # PIE (Position Independent Executable)
        if elf.pie:
            protections.append("PIE enabled (ASLR for binary)")
        else:
            vulnerabilities.append("No PIE - fixed binary addresses (ROP gadgets at known addresses)")

        # Stack Canary
        canary = getattr(elf, 'canary', None)
        if canary:
            protections.append("Stack canary present")
        else:
            vulnerabilities.append("No stack canary - buffer overflow possible")

        # RELRO
        try:
            if elf.full_relro:
                protections.append("Full RELRO (GOT read-only)")
            elif elf.relro:
                vulnerabilities.append("Partial RELRO - GOT overwrite possible")
            else:
                vulnerabilities.append("No RELRO - GOT fully writable")
        except AttributeError:
            vulnerabilities.append("RELRO status unknown")

        # Find interesting functions
        interesting_funcs = []
        for name in ["system", "execve", "win", "flag", "shell", "get_flag",
                      "print_flag", "ret2win", "backdoor", "secret"]:
            if name in elf.symbols:
                interesting_funcs.append(f"{name} @ {hex(elf.symbols[name])}")

        # Find PLT entries (useful for exploitation)
        plt_funcs = []
        for name in ["puts", "printf", "write", "system", "gets", "read",
                      "scanf", "fgets", "strcpy", "strcat"]:
            if name in elf.plt:
                plt_funcs.append(name)

        # Dangerous functions that indicate vulnerabilities
        dangerous = []
        for name in ["gets", "strcpy", "strcat", "sprintf", "scanf"]:
            if name in elf.plt:
                dangerous.append(name)

        # Find ROP gadgets count
        gadget_info = ""
        try:
            from pwn import ROP
            rop = ROP(elf)
            gadget_count = len(rop.gadgets)
            gadget_info = f"  ROP gadgets available: {gadget_count}"

            # Check for key gadgets
            key_gadgets = []
            for gadget_name in [["pop rdi", "ret"], ["pop rsi", "ret"],
                                ["pop rdx", "ret"], ["ret"]]:
                try:
                    addr = rop.find_gadget(gadget_name)[0]
                    key_gadgets.append(f"    {' ; '.join(gadget_name)} @ {hex(addr)}")
                except (IndexError, TypeError):
                    pass
            if key_gadgets:
                gadget_info += "\n  Key gadgets:\n" + "\n".join(key_gadgets)
        except Exception:
            pass

        # Build report
        lines = [
            f"=== Binary Security Analysis ===",
            f"  Binary: {self.target.path}",
            f"  Arch: {elf.arch} ({elf.bits}-bit)",
            f"  Entry: {hex(elf.entry)}",
            "",
        ]

        if protections:
            lines.append("  Protections:")
            for p in protections:
                lines.append(f"    [+] {p}")

        if vulnerabilities:
            lines.append("  Vulnerabilities:")
            for v in vulnerabilities:
                lines.append(f"    [-] {v}")

        if dangerous:
            lines.append(f"  Dangerous functions in PLT: {', '.join(dangerous)}")

        if interesting_funcs:
            lines.append("  Interesting functions:")
            for f in interesting_funcs:
                lines.append(f"    * {f}")

        if plt_funcs:
            lines.append(f"  Available PLT: {', '.join(plt_funcs)}")

        if gadget_info:
            lines.append(gadget_info)

        # Exploitation suggestions
        lines.append("")
        lines.append("  Suggested approach:")
        if not canary and not elf.pie:
            if dangerous:
                if interesting_funcs:
                    lines.append("    -> ret2win: overflow buffer, call win function")
                elif "puts" in elf.plt or "printf" in elf.plt:
                    lines.append("    -> ret2libc: leak libc via PLT, call system('/bin/sh')")
                elif not nx:
                    lines.append("    -> shellcode: NX disabled, inject shellcode on stack")
                else:
                    lines.append("    -> ROP chain: build chain from available gadgets")

        result = "\n".join(lines)
        self.manager.register_data(self, result)
