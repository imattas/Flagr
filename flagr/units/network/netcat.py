"""
Netcat-style connection for network service CTF challenges.

This unit connects to network services (host:port targets) and
interacts with them to extract flags. It handles common CTF patterns:

- Banner grabbing: reads initial data from service
- Math challenges: detects and solves arithmetic prompts
- Echo/input challenges: responds to common prompts
- Multi-round interaction: handles services requiring multiple exchanges
- Format string probing: sends %p patterns to detect format string vulns
- Menu-based challenges: tries common menu options

Targets can be specified as:
  - host:port
  - nc host port
  - host port
"""

import socket
import time
import operator
from typing import Any, Generator

import regex as re
from flagr.unit import NotApplicable
from flagr.unit import Unit as BaseUnit


# Pattern to match host:port or nc host port
HOST_PORT_PATTERN = re.compile(
    rb"(?:nc\s+)?(\S+)\s+(\d{1,5})",
    re.MULTILINE,
)

# Patterns for detecting math challenges
MATH_PATTERN = re.compile(
    rb"(\d+)\s*([+\-*/x%^])\s*(\d+)\s*[=?]",
    re.IGNORECASE,
)

# Common prompt patterns that expect input
PROMPT_PATTERNS = [
    re.compile(rb"(?:what|enter|give|type|input|send|answer|provide)[^:?]*[?:>]\s*$", re.IGNORECASE),
    re.compile(rb"[>$#]\s*$"),
    re.compile(rb":\s*$"),
    re.compile(rb"\?\s*$"),
    re.compile(rb"choice[:\s]*$", re.IGNORECASE),
    re.compile(rb"option[:\s]*$", re.IGNORECASE),
    re.compile(rb"name[?:>\s]*$", re.IGNORECASE),
    re.compile(rb"password[?:>\s]*$", re.IGNORECASE),
]

# Math operator lookup
OPERATORS = {
    b"+": operator.add,
    b"-": operator.sub,
    b"*": operator.mul,
    b"x": operator.mul,
    b"/": operator.floordiv,
    b"%": operator.mod,
    b"^": operator.xor,
}


def solve_math(data: bytes) -> bytes:
    """Try to find and solve a math expression in the data."""
    match = MATH_PATTERN.search(data)
    if match:
        a = int(match.group(1))
        op = match.group(2).lower()
        b = int(match.group(3))
        func = OPERATORS.get(op)
        if func:
            try:
                result = func(a, b)
                return str(result).encode()
            except (ZeroDivisionError, ValueError):
                pass
    return None


def recv_until_quiet(sock: socket.socket, timeout: float = 2.0, bufsize: int = 4096) -> bytes:
    """Receive data until the socket is quiet for `timeout` seconds."""
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(bufsize)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
        except (ConnectionResetError, BrokenPipeError):
            break
    return data


class Unit(BaseUnit):

    GROUPS = ["network", "netcat", "nc", "remote"]
    PRIORITY = 30
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

        # Don't apply to files or URLs
        if self.target.is_url or self.target.path:
            raise NotApplicable("not a network target")

        # Try to parse host:port from data
        data = self.target.raw
        if isinstance(data, str):
            data = data.encode()

        # Try "host:port" format first
        colon_match = re.search(rb"(\S+):(\d{1,5})\b", data)
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
        """Yield interaction strategies to try."""
        yield "banner"
        yield "math_solver"
        yield "interactive"

    def _connect(self) -> socket.socket:
        """Create and return a connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self._host, self._port))
        return sock

    def evaluate(self, case: Any):
        """Connect and interact based on the strategy."""
        try:
            if case == "banner":
                self._banner_grab()
            elif case == "math_solver":
                self._math_solver()
            elif case == "interactive":
                self._interactive_probe()
        except (socket.error, OSError, ConnectionRefusedError):
            pass

    def _banner_grab(self):
        """Connect and grab the banner, then try sending common inputs."""
        sock = self._connect()
        try:
            # Receive banner
            data = recv_until_quiet(sock, timeout=3.0)
            if data:
                self.manager.register_data(self, data)

            # Try sending a newline to trigger more output
            try:
                sock.sendall(b"\n")
                more = recv_until_quiet(sock, timeout=2.0)
                if more:
                    self.manager.register_data(self, more)
            except (socket.timeout, BrokenPipeError, OSError):
                pass
        finally:
            sock.close()

    def _math_solver(self):
        """Connect and try to solve math challenges (common in CTFs)."""
        sock = self._connect()
        try:
            rounds_solved = 0
            max_rounds = 200  # Some challenges have many rounds

            for _ in range(max_rounds):
                data = recv_until_quiet(sock, timeout=3.0)
                if not data:
                    break

                # Register all received data (may contain flags)
                self.manager.register_data(self, data)

                # Try to solve math
                answer = solve_math(data)
                if answer:
                    sock.sendall(answer + b"\n")
                    rounds_solved += 1
                    time.sleep(0.05)
                else:
                    # No math found, try common responses
                    break

            # Get final output after all rounds
            if rounds_solved > 0:
                final = recv_until_quiet(sock, timeout=3.0)
                if final:
                    self.manager.register_data(self, final)
        finally:
            sock.close()

    def _interactive_probe(self):
        """Try various common CTF interaction patterns."""
        common_inputs = [
            b"admin",
            b"flag",
            b"cat flag.txt",
            b"ls",
            b"1",
            b"yes",
            b"y",
            b"help",
            b"%p %p %p %p %p",  # format string probe
        ]

        for test_input in common_inputs:
            try:
                sock = self._connect()
                try:
                    # Get banner
                    banner = recv_until_quiet(sock, timeout=2.0)
                    if not banner:
                        continue

                    # Send test input
                    sock.sendall(test_input + b"\n")
                    time.sleep(0.3)

                    # Get response
                    response = recv_until_quiet(sock, timeout=2.0)
                    if response:
                        self.manager.register_data(self, response)

                        # If we see another prompt, try more interaction
                        has_prompt = any(p.search(response) for p in PROMPT_PATTERNS)
                        if has_prompt:
                            sock.sendall(b"flag\n")
                            time.sleep(0.3)
                            more = recv_until_quiet(sock, timeout=2.0)
                            if more:
                                self.manager.register_data(self, more)
                finally:
                    sock.close()
            except (socket.error, OSError, ConnectionRefusedError):
                continue
