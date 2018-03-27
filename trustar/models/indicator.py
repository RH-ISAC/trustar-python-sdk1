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
    Models an |Indicator_resource|.

    :ivar value: The indicator value; i.e. "www.evil.com"
    :ivar type: The type of indicator; i.e. "URL"
    :ivar priority_level: The priority level of the indicator
    :ivar correlation_count: The number of other indicators that are correlated with this indicator.
    :ivar whitelisted: Whether the indicator is whitelisted or not.
    :ivar weight: see |Indicator_resource| for details.
    :ivar reason: see |Indicator_resource| for details.

    :cvar TYPES: A list of all valid indicator types.
    """

    TYPES = IndicatorType.values()

    def __init__(self,
                 value,
                 type,
                 priority_level=None,
                 correlation_count=None,
                 whitelisted=None,
                 weight=None,
                 reason=None):

        self.value = value
        self.type = type
        self.priority_level = priority_level
        self.correlation_count = correlation_count
        self.whitelisted = whitelisted
        self.weight = weight
        self.reason = reason

    @classmethod
    def from_dict(cls, indicator):
        """
        Create an indicator object from a dictionary.

        :param indicator: The dictionary.
        :return: The indicator object.
        """

        return Indicator(value=indicator.get('value'),
                         type=indicator.get('indicatorType'),
                         priority_level=indicator.get('priorityLevel'),
                         correlation_count=indicator.get('correlationCount'),
                         whitelisted=indicator.get('whitelisted'),
                         weight=indicator.get('weight'),
                         reason=indicator.get('reason'))

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
            'indicatorType': self.type,
            'priorityLevel': self.priority_level,
            'correlationCount': self.correlation_count,
            'whitelisted': self.whitelisted,
            'weight': self.weight,
            'reason': self.reason
        }
