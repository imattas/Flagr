#!/usr/bin/env python3
from typing import Generator, Any

from flagr.manager import Manager
from flagr.target import Target
from flagr.unit import Unit as BaseUnit
from flagr.unit import NotApplicable


class Unit(BaseUnit):
    # Fill in your groups
    GROUPS = ["raw"]
    # This unit simply searches for flags, so we want to do it first
    PRIORITY = 0

    def __init__(self, manager: Manager, target: Target):
        super(Unit, self).__init__(manager, target)
        # This unit is always valid...

    def evaluate(self, case: Any) -> None:
        """
        Evaluate the target.
        :param case: A case returned by evaluate
        :return: None
        """

        # This is a very simple unit...
        self.manager.find_flag(self, self.target.raw)
