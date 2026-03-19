"""
Template-based challenge solver for common CTF network patterns.

Connects to a network service, detects the challenge type based on
prompts, and automatically solves multiple rounds. Supported types:

- Math: solve arithmetic expressions (e.g. "What is 123 + 456?")
- Base64: decode base64-encoded strings
- Hex: decode hex-encoded strings
- Reverse: reverse strings
- XOR: XOR data with a key

Handles multi-round challenges with timeout. Many CTF services send
N rounds of a challenge and reward a flag after completion.

Targets can be specified as:
  - host:port
  - nc host port
  - host port
"""

import base64
import binascii
import operator
import socket
import time
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

# Math expression pattern
MATH_PATTERN = re.compile(
    rb"(\d+)\s*([+\-*/x%^])\s*(\d+)\s*[=?]",
    re.IGNORECASE,
)

# Operator lookup
OPERATORS = {
    b"+": operator.add,
    b"-": operator.sub,
    b"*": operator.mul,
    b"x": operator.mul,
    b"/": operator.floordiv,
    b"%": operator.mod,
    b"^": operator.xor,
}

# Patterns used to detect challenge type from service output
MATH_DETECT = re.compile(
    rb"(\d+)\s*[+\-*/x%^]\s*\d+",
    re.IGNORECASE,
)
BASE64_DETECT = re.compile(
    rb"(?:base64|decode|b64)[^:]*:\s*([A-Za-z0-9+/=]{4,})",
    re.IGNORECASE,
)
HEX_DETECT = re.compile(
    rb"(?:hex|decode|unhex)[^:]*:\s*([0-9a-fA-F]{4,})",
    re.IGNORECASE,
)
REVERSE_DETECT = re.compile(
    rb"(?:reverse|flip|backwards)[^:]*:\s*(\S+)",
    re.IGNORECASE,
)
XOR_DETECT = re.compile(
    rb"(?:xor)[^:]*(?:key\s*[=:]\s*(\d+))?[^:]*:\s*([0-9a-fA-F]+)",
    re.IGNORECASE,
)


def recv_until_quiet(sock, timeout=2.0, bufsize=4096):
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


def solve_math(data):
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


def solve_base64(data):
    """Try to find and decode a base64 challenge."""
    match = BASE64_DETECT.search(data)
    if match:
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded)
            return decoded
        except Exception:
            pass
    return None


def solve_hex(data):
    """Try to find and decode a hex challenge."""
    match = HEX_DETECT.search(data)
    if match:
        hex_str = match.group(1)
        try:
            decoded = binascii.unhexlify(hex_str)
            return decoded
        except Exception:
            pass
    return None


def solve_reverse(data):
    """Try to find and reverse a string challenge."""
    match = REVERSE_DETECT.search(data)
    if match:
        s = match.group(1)
        return s[::-1]
    return None


def solve_xor(data):
    """Try to find and solve a XOR challenge."""
    match = XOR_DETECT.search(data)
    if match:
        key_str = match.group(1)
        hex_data = match.group(2)
        try:
            raw = binascii.unhexlify(hex_data)
        except Exception:
            return None

        # Default XOR key
        key = int(key_str) if key_str else 0x42
        result = bytes([b ^ key for b in raw])
        return result
    return None


def detect_and_solve(data):
    """
    Detect the challenge type from the data and return the answer.
    Returns (challenge_type, answer) or (None, None).
    """
    # Try each solver in order of specificity
    answer = solve_base64(data)
    if answer is not None:
        return "base64", answer

    answer = solve_hex(data)
    if answer is not None:
        return "hex", answer

    answer = solve_reverse(data)
    if answer is not None:
        return "reverse", answer

    answer = solve_xor(data)
    if answer is not None:
        return "xor", answer

    answer = solve_math(data)
    if answer is not None:
        return "math", answer

    return None, None


class Unit(BaseUnit):

    GROUPS = ["network", "solver", "remote"]
    PRIORITY = 30
    RECURSE_SELF = False
    NO_RECURSE = True

    def __init__(self, *args, **kwargs):
        super(Unit, self).__init__(*args, **kwargs)

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

    def _connect(self):
        """Create and return a connected socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self._host, self._port))
        return sock

    def enumerate(self) -> Generator[Any, None, None]:
        """Yield a single case -- we auto-detect the challenge type."""
        yield "auto_detect"

    def evaluate(self, case: Any):
        """
        Connect to the service, detect the challenge type from the first
        prompt, then solve rounds until the service stops or we hit a
        timeout / max rounds.
        """
        max_rounds = 500
        round_timeout = 5.0

        try:
            sock = self._connect()
        except (socket.error, OSError):
            return

        try:
            rounds_solved = 0
            challenge_type = None

            for _ in range(max_rounds):
                data = recv_until_quiet(sock, timeout=round_timeout)
                if not data:
                    break

                # Register all received data (may contain flags)
                self.manager.register_data(self, data)

                # Detect and solve
                detected_type, answer = detect_and_solve(data)

                if answer is not None:
                    if challenge_type is None:
                        challenge_type = detected_type

                    sock.sendall(answer + b"\n")
                    rounds_solved += 1
                    time.sleep(0.05)
                else:
                    # Could not detect a challenge in this round
                    # If we already solved some rounds, grab final output
                    if rounds_solved > 0:
                        break
                    # First round and no detection -- try sending data as-is
                    # to provoke a different prompt
                    try:
                        sock.sendall(b"\n")
                        time.sleep(0.3)
                        retry_data = recv_until_quiet(sock, timeout=round_timeout)
                        if retry_data:
                            self.manager.register_data(self, retry_data)
                            detected_type, answer = detect_and_solve(retry_data)
                            if answer is not None:
                                challenge_type = detected_type
                                sock.sendall(answer + b"\n")
                                rounds_solved += 1
                                time.sleep(0.05)
                                continue
                    except (socket.error, OSError):
                        pass
                    break

            # Get final output after all rounds
            if rounds_solved > 0:
                try:
                    final = recv_until_quiet(sock, timeout=round_timeout)
                    if final:
                        self.manager.register_data(self, final)
                except (socket.error, OSError):
                    pass

                summary = (
                    f"=== Template Solver Complete ===\n"
                    f"  Target: {self._host}:{self._port}\n"
                    f"  Challenge type: {challenge_type}\n"
                    f"  Rounds solved: {rounds_solved}"
                )
                self.manager.register_data(self, summary)

        except (socket.error, OSError):
            pass
        finally:
            sock.close()
