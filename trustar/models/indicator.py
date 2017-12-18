# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# external imports
import json


class Indicator:
    """
    Models an indicator of compromise.
    """

    def __init__(self, value, type, priority_level=None):
        self.value = value
        self.type = type
        self.priority_level = priority_level

    @staticmethod
    def from_dict(indicator):
        """
        Create an indicator object from a dictionary.
        :param indicator: The dictionary.
        :return: The indicator object.
        """
        return Indicator(value=indicator.get('value'),
                         type=indicator.get('type'),
                         priority_level=indicator.get('priorityLevel'))

    def to_dict(self):
        """
        :return: A dictionary representation of the indicator.
        """
        return {
            'value': self.value,
            'type': self.type,
            'priority_level': self.priority_level
        }

    def __str__(self):
        return json.dumps(self.to_dict())
