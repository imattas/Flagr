"""
File carving from binary blobs

This unit searches binary data for known magic byte signatures of common
file formats and extracts each embedded file as an artifact. Supported
formats include ZIP, PNG, GIF, JPEG, PDF, RAR, 7z, and ELF.

The unit inherits from :class:`flagr.unit.FileUnit` to ensure the target
is a file.
"""

import struct
from typing import Any

from flagr.unit import FileUnit, NotApplicable


# Magic bytes and their associated file type info
# Each entry: (magic_bytes, extension, description, max_size_or_None)
SIGNATURES = [
    (b"PK\x03\x04", "zip", "ZIP archive", 50 * 1024 * 1024),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG image", 50 * 1024 * 1024),
    (b"GIF87a", "gif", "GIF87a image", 20 * 1024 * 1024),
    (b"GIF89a", "gif", "GIF89a image", 20 * 1024 * 1024),
    (b"\xff\xd8\xff", "jpg", "JPEG image", 50 * 1024 * 1024),
    (b"%PDF", "pdf", "PDF document", 100 * 1024 * 1024),
    (b"Rar!\x1a\x07", "rar", "RAR archive", 50 * 1024 * 1024),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip archive", 50 * 1024 * 1024),
    (b"\x7fELF", "elf", "ELF binary", 50 * 1024 * 1024),
]


class Unit(FileUnit):

    GROUPS = ["forensics", "carve", "extract"]
    """
    These are "tags" for a unit. Considering it is a Forensics unit,
    "forensics" is included, as well as "carve" and "extract".
    """

    PRIORITY = 30
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a moderately
    high priority.
    """

    BLOCKED_GROUPS = ["carve"]
    """
    Prevent recursion into other carving units to avoid infinite loops.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor ensures the target is a file.
        """
        super(Unit, self).__init__(*args, **kwargs)

    def evaluate(self, case: Any) -> None:
        """
        Evaluate the target. Search the file for known magic byte signatures
        and extract each found embedded file as an artifact.

        :param case: A case returned by ``enumerate``. Not used for this unit.
        :return: None.
        """

        try:
            with open(self.target.path, "rb") as f:
                data = f.read()
        except Exception:
            return

        if len(data) == 0:
            return

        found_files = []

        for magic, ext, desc, max_size in SIGNATURES:
            offset = 0
            count = 0

            while offset < len(data):
                idx = data.find(magic, offset)
                if idx == -1:
                    break

                # Skip if this is at the very start and matches the whole file
                # (we don't want to carve the file itself)
                if idx == 0 and len(found_files) == 0:
                    # Check if this appears to be the main file format
                    offset = idx + len(magic)
                    # Still record if there are more instances later
                    continue

                # Determine the end of the embedded file
                end = self._find_end(data, idx, magic, ext, max_size)

                if end <= idx + len(magic):
                    offset = idx + len(magic)
                    continue

                # Extract the embedded data
                carved = data[idx:end]

                # Don't carve tiny files (likely false positives)
                if len(carved) < 8:
                    offset = idx + len(magic)
                    continue

                count += 1
                artifact_name = "carved_{:04x}_{}{}.{}".format(idx, ext, count, ext)

                try:
                    artifact_path, artifact_fh = self.generate_artifact(
                        artifact_name, mode="wb", create=True
                    )
                    artifact_fh.write(carved)
                    artifact_fh.close()
                    self.manager.register_artifact(self, artifact_path)
                    found_files.append(
                        "{} at offset 0x{:x} ({} bytes)".format(desc, idx, len(carved))
                    )
                except Exception:
                    pass

                offset = idx + len(magic)

        # Also check if the first match at offset 0 has additional files after it
        # Re-scan from offset 0 for all signatures if we skipped the start
        for magic, ext, desc, max_size in SIGNATURES:
            if data.startswith(magic):
                # Find additional instances after the first
                second = data.find(magic, len(magic))
                if second != -1:
                    end = self._find_end(data, second, magic, ext, max_size)
                    carved = data[second:end]
                    if len(carved) >= 8:
                        artifact_name = "carved_{:04x}_embedded.{}".format(second, ext)
                        try:
                            artifact_path, artifact_fh = self.generate_artifact(
                                artifact_name, mode="wb", create=True
                            )
                            artifact_fh.write(carved)
                            artifact_fh.close()
                            self.manager.register_artifact(self, artifact_path)
                            found_files.append(
                                "{} at offset 0x{:x} ({} bytes)".format(
                                    desc, second, len(carved)
                                )
                            )
                        except Exception:
                            pass

        if found_files:
            self.manager.register_data(self, {"carved_files": found_files})

    def _find_end(self, data, start, magic, ext, max_size):
        """
        Attempt to find the end of an embedded file starting at the given offset.
        Uses format-specific end markers where possible, otherwise uses the
        next magic signature or max_size as the boundary.

        :param data: The full file data.
        :param start: Start offset of the embedded file.
        :param magic: The magic bytes that were matched.
        :param ext: The file extension/type.
        :param max_size: Maximum size to extract.
        :return: End offset.
        """

        limit = min(start + max_size, len(data))

        if ext == "png":
            # Look for IEND chunk
            iend = data.find(b"IEND", start + 8)
            if iend != -1:
                # IEND chunk: 4 byte length (0) + 4 byte type + 4 byte CRC
                return min(iend + 8 + 4, limit)

        elif ext == "jpg":
            # Look for JPEG EOI marker
            eoi = data.find(b"\xff\xd9", start + 2)
            if eoi != -1:
                return min(eoi + 2, limit)

        elif ext == "gif":
            # Look for GIF trailer
            trailer = data.find(b"\x00\x3b", start + 6)
            if trailer != -1:
                return min(trailer + 2, limit)

        elif ext == "pdf":
            # Look for %%EOF marker
            eof = data.find(b"%%EOF", start + 4)
            if eof != -1:
                return min(eof + 5, limit)

        elif ext == "zip":
            # Look for end of central directory record
            eocd = data.find(b"PK\x05\x06", start + 4)
            if eocd != -1:
                # EOCD is at least 22 bytes
                return min(eocd + 22, limit)

        elif ext == "elf":
            # Try to parse ELF header for file size
            try:
                if data[start + 4] == 1:  # 32-bit
                    e_shoff = struct.unpack("<I", data[start + 32 : start + 36])[0]
                    e_shentsize = struct.unpack(
                        "<H", data[start + 46 : start + 48]
                    )[0]
                    e_shnum = struct.unpack("<H", data[start + 48 : start + 50])[0]
                    return min(start + e_shoff + (e_shentsize * e_shnum), limit)
                elif data[start + 4] == 2:  # 64-bit
                    e_shoff = struct.unpack("<Q", data[start + 40 : start + 48])[0]
                    e_shentsize = struct.unpack(
                        "<H", data[start + 58 : start + 60]
                    )[0]
                    e_shnum = struct.unpack("<H", data[start + 60 : start + 62])[0]
                    return min(start + e_shoff + (e_shentsize * e_shnum), limit)
            except Exception:
                pass

        # Default: find the next magic signature to use as boundary
        nearest_next = limit
        for other_magic, _, _, _ in SIGNATURES:
            idx = data.find(other_magic, start + len(magic))
            if idx != -1 and idx < nearest_next:
                nearest_next = idx

        return nearest_next
