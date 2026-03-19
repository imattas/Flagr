from tests import FlagrTest
from base64 import b64encode


class TestBase64(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_orchestra(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        auto=yes
        """,
            target=b64encode(b"FLAG{base64}"),
            correct_flag="FLAG{base64}",
        )
