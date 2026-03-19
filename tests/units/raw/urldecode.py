from tests import FlagrTest


class TestUrldecode(FlagrTest):
    """ Test flagr.units.raw.urldecode """

    def test_urldecode(self):
        flag = "FLAG{urldecode}"
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        units=urldecode
        auto=yes
        """,
            target="".join(["%" + hex(ord(c))[2:] for c in flag]),
            correct_flag=flag,
        )
