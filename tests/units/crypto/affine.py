from tests import FlagrTest
from base64 import b85encode


class TestAffine(FlagrTest):
    """ Test flagr.units.crypto.affine """

    def test_affine(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG{.*?}
        units=affine
        auto=yes
        """,
            target=b"HLIM{HLIM}",
            correct_flag="FLAG{FLAG}",
        )
