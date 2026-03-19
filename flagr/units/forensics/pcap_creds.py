"""
PCAP credential extraction

This unit parses pcap files and extracts credentials from common protocols.
It searches for HTTP Basic Authentication headers (base64 decoded),
HTTP POST form data containing username/password fields, FTP USER/PASS
commands, and other plaintext credentials.

The unit inherits from :class:`flagr.unit.FileUnit` to ensure the target
is a pcap file. It attempts to use scapy for parsing, falling back to
raw pcap parsing if scapy is not available.
"""

import base64
import struct
import re
from typing import Any

from flagr.unit import FileUnit, NotApplicable

# Try to import scapy
try:
    from scapy.all import rdpcap, TCP, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class Unit(FileUnit):

    GROUPS = ["forensics", "pcap", "network"]
    """
    These are "tags" for a unit. Considering it is a Forensics unit,
    "forensics" is included, as well as "pcap" and "network".
    """

    PRIORITY = 30
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a moderately
    high priority.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to provide a keyword for the
        ``FileUnit``, ensuring the provided target is a pcap file.
        """
        super(Unit, self).__init__(*args, **kwargs, keywords=["pcap", "capture"])

    def evaluate(self, case: Any) -> None:
        """
        Evaluate the target. Parse the pcap file and look for credentials
        in HTTP, FTP, and other plaintext protocols.

        :param case: A case returned by ``enumerate``. Not used for this unit.
        :return: None.
        """

        if HAS_SCAPY:
            self._evaluate_scapy()
        else:
            self._evaluate_raw()

    def _evaluate_scapy(self) -> None:
        """
        Parse the pcap using scapy and extract credentials.
        """
        try:
            packets = rdpcap(self.target.path)
        except Exception:
            return

        credentials = []

        for pkt in packets:
            try:
                if not pkt.haslayer(Raw):
                    continue

                payload = pkt[Raw].load

                try:
                    payload_str = payload.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # HTTP Basic Authentication
                creds = self._extract_http_basic(payload_str)
                if creds:
                    credentials.extend(creds)

                # HTTP POST form data
                creds = self._extract_http_post(payload_str)
                if creds:
                    credentials.extend(creds)

                # FTP credentials
                creds = self._extract_ftp(payload_str)
                if creds:
                    credentials.extend(creds)

                # Generic plaintext credential patterns
                creds = self._extract_plaintext(payload_str)
                if creds:
                    credentials.extend(creds)

            except Exception:
                continue

        self._register_credentials(credentials)

    def _evaluate_raw(self) -> None:
        """
        Parse the pcap using raw byte reading when scapy is not available.
        Supports both pcap and pcapng formats at a basic level.
        """
        try:
            with open(self.target.path, "rb") as f:
                data = f.read()
        except Exception:
            return

        credentials = []

        # Try to extract readable strings and search for credential patterns
        # This is a simpler approach that works without scapy
        try:
            # Extract ASCII strings of length >= 4 from the pcap
            ascii_pattern = re.compile(rb"[\x20-\x7e]{4,}")
            strings = ascii_pattern.findall(data)

            for s in strings:
                try:
                    text = s.decode("ascii")
                except Exception:
                    continue

                # HTTP Basic Authentication
                creds = self._extract_http_basic(text)
                if creds:
                    credentials.extend(creds)

                # HTTP POST form data
                creds = self._extract_http_post(text)
                if creds:
                    credentials.extend(creds)

                # FTP credentials
                creds = self._extract_ftp(text)
                if creds:
                    credentials.extend(creds)

                # Generic plaintext credential patterns
                creds = self._extract_plaintext(text)
                if creds:
                    credentials.extend(creds)

        except Exception:
            pass

        self._register_credentials(credentials)

    def _extract_http_basic(self, text):
        """
        Extract HTTP Basic Authentication credentials.
        Looks for Authorization: Basic <base64> headers.
        """
        results = []
        pattern = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
        for match in pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="replace")
                results.append("HTTP Basic Auth: {}".format(decoded))
            except Exception:
                pass
        return results

    def _extract_http_post(self, text):
        """
        Extract credentials from HTTP POST form data.
        Looks for username/password fields in URL-encoded form data.
        """
        results = []
        # Look for common form field patterns
        patterns = [
            re.compile(
                r"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:pass(?:word)?|pwd)=([^&\s]+).*?(?:user(?:name)?|login|email)=([^&\s]+)",
                re.IGNORECASE,
            ),
        ]
        for pattern in patterns:
            for match in pattern.finditer(text):
                groups = match.groups()
                if len(groups) == 2:
                    results.append("HTTP POST Creds: {}:{}".format(groups[0], groups[1]))
        return results

    def _extract_ftp(self, text):
        """
        Extract FTP USER and PASS commands.
        """
        results = []
        user_pattern = re.compile(r"USER\s+(.+?)(?:\r?\n|$)")
        pass_pattern = re.compile(r"PASS\s+(.+?)(?:\r?\n|$)")

        users = user_pattern.findall(text)
        passes = pass_pattern.findall(text)

        for user in users:
            results.append("FTP USER: {}".format(user.strip()))
        for passwd in passes:
            results.append("FTP PASS: {}".format(passwd.strip()))

        return results

    def _extract_plaintext(self, text):
        """
        Extract generic plaintext credential patterns.
        """
        results = []
        patterns = [
            re.compile(
                r"(?:password|passwd|pwd)\s*[:=]\s*([^\s&]{1,64})", re.IGNORECASE
            ),
            re.compile(
                r"(?:username|user|login)\s*[:=]\s*([^\s&]{1,64})", re.IGNORECASE
            ),
        ]
        for pattern in patterns:
            for match in pattern.finditer(text):
                results.append("Plaintext cred: {}".format(match.group(0).strip()))
        return results

    def _register_credentials(self, credentials):
        """
        Deduplicate and register found credentials.
        """
        if not credentials:
            return

        # Deduplicate
        seen = set()
        unique = []
        for cred in credentials:
            if cred not in seen:
                seen.add(cred)
                unique.append(cred)

        # Register each credential
        for cred in unique:
            self.manager.register_data(self, cred)

        # Write credentials to artifact
        try:
            artifact_path, artifact_fh = self.generate_artifact(
                "credentials.txt", mode="w", create=True
            )
            artifact_fh.write("\n".join(unique))
            artifact_fh.close()
            self.manager.register_artifact(self, artifact_path)
        except Exception:
            pass
