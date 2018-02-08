# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library
from six import string_types

# package imports
from .base import ModelBase
from .enum import *


class Indicator(ModelBase):
    """
    Models an indicator of compromise.

    :ivar value: The indicator value; i.e. "www.evil.com"
    :ivar type: The type of indicator; i.e. "URL"
    :ivar priority_level: The priority level of the indicator
    :ivar correlation_count: The number of other indicators that are correlated with this indicator.

    :cvar TYPES: A list of all valid indicator types.
    :cvar PRIORITY_LEVELS: A list of all possible priority levels.
    """

    TYPES = IndicatorType.values()
    PRIORITY_LEVELS = PriorityLevel.values()

    def __init__(self, value, type, priority_level=None, correlation_count=None):
        self.value = value
        self.type = type
        self.priority_level = priority_level
        self.correlation_count = correlation_count

    @staticmethod
    def from_dict(indicator):
        """
        Create an indicator object from a dictionary.

        :param indicator: The dictionary.
        :return: The indicator object.
        """

        return Indicator(value=indicator.get('value'),
                         type=indicator.get('indicatorType'),
                         priority_level=indicator.get('priorityLevel'),
                         correlation_count=indicator.get('correlationCount'))

    def to_dict(self, remove_nones=False):
        """
        Creates a dictionary representation of the indicator.

        :param remove_nones: Whether ``None`` values should be filtered out of the dictionary.  Defaults to ``False``.
        :return: A dictionary representation of the indicator.
        """

        if remove_nones:
            return super().to_dict(remove_nones=True)

        return {
            'value': self.value,
            'type': self.type,
            'priorityLevel': self.priority_level,
            'correlationCount': self.correlation_count
        }
