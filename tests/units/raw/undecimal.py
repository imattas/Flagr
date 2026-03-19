from tests import FlagrTest


class TestUndecimal(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_undecimal(self):
        flag = "FLAG{unbinary}"
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        auto=yes
        """,
            target=" ".join(str(ord(x)) for x in flag),
            correct_flag=flag,
        )
