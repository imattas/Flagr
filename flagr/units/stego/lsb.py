"""
LSB (Least Significant Bit) steganography extraction

This unit extracts the least significant bits from image pixel channels
using PIL/Pillow. It tries extracting LSBs from all RGB channels combined,
as well as each individual R, G, B channel separately, then converts
the collected bits to bytes and registers the results.

The unit inherits from :class:`flagr.unit.FileUnit` to ensure the target
is an image file.
"""

from typing import Generator, Any

from flagr.unit import FileUnit, NotApplicable

try:
    from PIL import Image
except ImportError:
    Image = None


class Unit(FileUnit):

    GROUPS = ["stego", "lsb", "image"]
    """
    These are "tags" for a unit. Considering it is a Stego unit, "stego"
    is included, as well as "lsb" and "image".
    """

    PRIORITY = 35
    """
    Priority works with 0 being the highest priority, and 100 being the
    lowest priority. 50 is the default priority. This unit has a moderately
    high priority.
    """

    def __init__(self, *args, **kwargs):
        """
        The constructor is included to provide a keyword for the
        ``FileUnit``, ensuring the provided target is an image file.
        """
        if Image is None:
            raise NotApplicable("PIL/Pillow is not installed")

        super(Unit, self).__init__(*args, **kwargs, keywords=["PNG", "image"])

    def enumerate(self) -> Generator[Any, None, None]:
        """
        Yield extraction modes: all channels combined, then each
        individual channel (R, G, B).

        :return: Generator of extraction mode strings.
        """
        yield "rgb"
        yield "r"
        yield "g"
        yield "b"

    def evaluate(self, case: Any) -> None:
        """
        Evaluate the target. Open the image with Pillow, extract LSBs
        from the specified channel(s), convert bits to bytes, and register
        any results.

        :param case: A case returned by ``enumerate``. For this unit,
        the case is the channel extraction mode ("rgb", "r", "g", "b").

        :return: None.
        """

        try:
            img = Image.open(self.target.path)
            img = img.convert("RGB")
            pixels = img.load()
            width, height = img.size
        except Exception:
            return

        bits = []
        channel_map = {"r": 0, "g": 1, "b": 2}

        try:
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]

                    if case == "rgb":
                        # Extract LSB from R, G, B in order
                        bits.append(pixel[0] & 1)
                        bits.append(pixel[1] & 1)
                        bits.append(pixel[2] & 1)
                    else:
                        # Extract LSB from a single channel
                        channel_idx = channel_map.get(case, 0)
                        bits.append(pixel[channel_idx] & 1)
        except Exception:
            return

        # Convert bits to bytes
        extracted = self._bits_to_bytes(bits)

        if not extracted:
            return

        # Check if the extracted data contains anything meaningful
        # (not all null bytes or all the same byte)
        stripped = extracted.rstrip(b"\x00")
        if not stripped:
            return

        # Write extracted data as artifact
        try:
            artifact_name = "lsb_{}.bin".format(case)
            artifact_path, artifact_fh = self.generate_artifact(
                artifact_name, mode="wb", create=True
            )
            artifact_fh.write(extracted)
            artifact_fh.close()
            self.manager.register_artifact(self, artifact_path)
        except Exception:
            pass

        # Also try to interpret as text and register
        try:
            # Take a reasonable sample to look for flags
            sample = stripped[:4096]
            text = sample.decode("utf-8", errors="ignore")
            # Filter to printable characters
            printable = "".join(c for c in text if c.isprintable() or c in "\n\r\t")
            if len(printable) > 4:
                self.manager.register_data(self, printable)
        except Exception:
            pass

    @staticmethod
    def _bits_to_bytes(bits):
        """
        Convert a list of bits (0/1 integers) into a bytes object.

        :param bits: List of bit values.
        :return: bytes object.
        """
        result = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for bit in bits[i : i + 8]:
                byte = (byte << 1) | bit
            result.append(byte)
        return bytes(result)
