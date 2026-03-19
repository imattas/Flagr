from tests import FlagrTest


class TestExiftool(FlagrTest):
    """ Test flagr.units.raw.exiftool """

    def test_woof64(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=USCGA{.*?}
        units=exiftool
        auto=yes
        """,
            target="./tests/cases/woof64.jpg",
            correct_flag="USCGA{the_best_base_is_the_base64}",
        )
