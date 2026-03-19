from tests import FlagrTest


class TestQRCode(FlagrTest):
    """ Test flagr.units.raw.strings """

    def test_qrcode(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=USCGA{.*?}
        auto=yes
        """,
            target="./tests/cases/qrcode.png",
            correct_flag="USCGA{is_this_ecoin_from_mr_robot}",
        )
