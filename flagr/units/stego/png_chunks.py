"""
PNG chunk analysis

This unit parses a PNG file and extracts information about its chunks.
It reads the IHDR, tEXt, zTXt, iTXt, and any non-standard chunks,
registering text chunk data and detecting suspicious chunk types or
data appended after the IEND marker.

The unit inherits from :class:`flagr.unit.FileUnit` to ensure the target
is a PNG file.
"""

import struct
import zlib
from typing import Any

from flagr.unit import FileUnit, NotApplicable


# Standard PNG chunk types
STANDARD_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"cHRM", b"gAMA", b"iCCP", b"sBIT",
    b"sRGB", b"bKGD", b"hIST", b"tRNS",
    b"pHYs", b"sPLT", b"tIME", b"iTXt",
    b"tEXt", b"zTXt", b"acTL", b"fcTL",
    b"fdAT", b"eXIf", b"oFFs", b"sCAL",
    b"pCAL", b"sTER", b"dSIG",
}

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class Unit(FileUnit):

    GROUPS = ["stego", "png", "png_chunks"]
    """
    These are "tags" for a unit. Considering it is a Stego unit, "stego"
    is included, as well as "png" and the unit name "png_chunks".
    """

    PRIORITY = 25
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a high
    priority for PNG files.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to provide a keyword for the
        ``FileUnit``, ensuring the provided target is a PNG file.
        """
        super(Unit, self).__init__(*args, **kwargs, keywords=["PNG"])

    def evaluate(self, case: Any) -> None:
        """
        Evaluate the target. Parse the PNG file for chunks and report
        any interesting findings such as text chunks, non-standard chunks,
        or data appended after the IEND marker.

        :param case: A case returned by ``enumerate``. Not used for this unit.
        :return: None.
        """

        try:
            with open(self.target.path, "rb") as f:
                data = f.read()
        except Exception:
            return

        # Verify PNG signature
        if not data.startswith(PNG_SIGNATURE):
            return

        offset = 8  # Skip PNG signature
        chunks = []
        iend_offset = None
        text_data = []
        suspicious_chunks = []

        while offset < len(data):
            # Each chunk: 4 bytes length, 4 bytes type, data, 4 bytes CRC
            if offset + 8 > len(data):
                break

            try:
                length = struct.unpack(">I", data[offset : offset + 4])[0]
                chunk_type = data[offset + 4 : offset + 8]
            except struct.error:
                break

            chunk_data_start = offset + 8
            chunk_data_end = chunk_data_start + length

            if chunk_data_end + 4 > len(data):
                # Truncated chunk
                break

            chunk_data = data[chunk_data_start:chunk_data_end]

            chunks.append(
                {
                    "type": chunk_type.decode("latin-1"),
                    "offset": offset,
                    "length": length,
                }
            )

            # Parse IHDR
            if chunk_type == b"IHDR" and length >= 13:
                try:
                    width = struct.unpack(">I", chunk_data[0:4])[0]
                    height = struct.unpack(">I", chunk_data[4:8])[0]
                    bit_depth = chunk_data[8]
                    color_type = chunk_data[9]
                    text_data.append(
                        "IHDR: {}x{}, bit_depth={}, color_type={}".format(
                            width, height, bit_depth, color_type
                        )
                    )
                except Exception:
                    pass

            # Parse tEXt chunks (keyword\x00text)
            elif chunk_type == b"tEXt":
                try:
                    null_idx = chunk_data.index(b"\x00")
                    keyword = chunk_data[:null_idx].decode("latin-1")
                    text_value = chunk_data[null_idx + 1 :].decode("latin-1")
                    text_data.append("tEXt: {}={}".format(keyword, text_value))
                except Exception:
                    pass

            # Parse zTXt chunks (keyword\x00compression_method\x00compressed_text)
            elif chunk_type == b"zTXt":
                try:
                    null_idx = chunk_data.index(b"\x00")
                    keyword = chunk_data[:null_idx].decode("latin-1")
                    # compression method is at null_idx+1, compressed data follows
                    compressed = chunk_data[null_idx + 2 :]
                    text_value = zlib.decompress(compressed).decode("latin-1")
                    text_data.append("zTXt: {}={}".format(keyword, text_value))
                except Exception:
                    pass

            # Parse iTXt chunks
            elif chunk_type == b"iTXt":
                try:
                    null_idx = chunk_data.index(b"\x00")
                    keyword = chunk_data[:null_idx].decode("utf-8")
                    rest = chunk_data[null_idx + 1 :]
                    # compression flag, compression method, then two null-separated strings
                    compression_flag = rest[0]
                    # Skip compression_method, language_tag, translated_keyword
                    rest = rest[2:]  # skip compression flag and method
                    parts = rest.split(b"\x00", 2)
                    if len(parts) >= 3:
                        text_value = parts[2]
                    elif len(parts) >= 1:
                        text_value = parts[-1]
                    else:
                        text_value = rest

                    if compression_flag:
                        text_value = zlib.decompress(text_value)
                    text_data.append(
                        "iTXt: {}={}".format(keyword, text_value.decode("utf-8", errors="replace"))
                    )
                except Exception:
                    pass

            # Check for non-standard chunk types
            if chunk_type not in STANDARD_CHUNKS:
                suspicious_chunks.append(
                    "Non-standard chunk: {} at offset {} ({} bytes)".format(
                        chunk_type.decode("latin-1"), offset, length
                    )
                )

            # Track IEND position
            if chunk_type == b"IEND":
                iend_offset = offset + 8 + length + 4  # past CRC
                break

            # Move to next chunk (length + type + data + CRC)
            offset = chunk_data_end + 4

        # Check for data after IEND
        trailing_data = None
        if iend_offset is not None and iend_offset < len(data):
            trailing_bytes = data[iend_offset:]
            trailing_data = "Data after IEND: {} bytes".format(len(trailing_bytes))

            # Write trailing data as artifact
            try:
                artifact_path, artifact_fh = self.generate_artifact(
                    "trailing_data.bin", mode="wb", create=True
                )
                artifact_fh.write(trailing_bytes)
                artifact_fh.close()
                self.manager.register_artifact(self, artifact_path)
            except Exception:
                pass

        # Build result
        result = {}

        if text_data:
            result["text_chunks"] = text_data
            # Register each text chunk for flag scanning
            for entry in text_data:
                self.manager.register_data(self, entry)

        if suspicious_chunks:
            result["suspicious_chunks"] = suspicious_chunks
            for entry in suspicious_chunks:
                self.manager.register_data(self, entry)

        if trailing_data:
            result["trailing_data"] = trailing_data
            self.manager.register_data(self, trailing_data)

        if chunks:
            result["chunk_summary"] = [
                "{} ({} bytes)".format(c["type"], c["length"]) for c in chunks
            ]

        if result:
            self.manager.register_data(self, result)
