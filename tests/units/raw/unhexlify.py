from tests import FlagrTest
from binascii import hexlify


class TestUnhexlify(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_unhexlify(self):
        flag = b"FLAG{unhexlify}"
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        auto=yes
        """,
            target=hexlify(flag),
            correct_flag=flag,
        )
