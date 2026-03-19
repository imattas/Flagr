from tests import FlagrTest
from base64 import b32encode


class TestBase32(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_base32(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        auto=yes
        """,
            target=b32encode(b"FLAG{base32}"),
            correct_flag="FLAG{base32}",
        )
