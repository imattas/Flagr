from tests import FlagrTest
from base64 import b85encode


class TestAscii85(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_ascii85(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        auto=yes
        """,
            target=b85encode(b"FLAG{base85}"),
            correct_flag="FLAG{base85}",
        )
