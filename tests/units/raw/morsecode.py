from tests import FlagrTest


class TestMorsecode(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_moresecode(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=^flag.*$
        auto=yes
        """,
            target="..-. .-.. .- --. -- --- .-. ... . -.-. --- -.. .",
            correct_flag="FLAGMORSECODE",
        )
