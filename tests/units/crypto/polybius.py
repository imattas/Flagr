#!/usr/bin/env python3
from tests import FlagrTest


class TestPolybius(FlagrTest):
    """ Test polybius functionality """

    def test_polybius(self):
        self.flagr_test(
            config=r"""
        [manager]
        flag-format=FLAG[^ ]*
        units=polybius
        auto=no
        """,
            target=b"213111223534315412244543434145114215",
            correct_flag="FLAGPOLYBIUSSQUARE",
        )
