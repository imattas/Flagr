from tests import FlagrTest


class TestAtBash(FlagrTest):
    """ Test flagr.units.crypto.atbash """

    def test_atbash(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        units=atbash
        auto=yes
        """,
            target=b"UOZT{UOZT}",
            correct_flag="FLAG{FLAG}",
        )
