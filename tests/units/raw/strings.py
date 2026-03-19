from tests import FlagrTest


class TestStrings(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_orchestra(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=USCGA{.*?}
        auto=yes
        """,
            target="./tests/cases/orchestra",
            correct_flag="USCGA{strings}",
        )
