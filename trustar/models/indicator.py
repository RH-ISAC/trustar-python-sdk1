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

    Attributes:
        :ivar value: The indicator value; i.e. "www.evil.com"
        :ivar type: The type of indicator; i.e. "URL"
        :ivar priority_level: The priority level of the indicator
        :ivar correlation_count: The number of other indicators that are correlated with this indicator.

        :cvar TYPES: A list of all valid indicator types.
        :cvar PRIORITY_LEVELS: A list of all possible priority levels.
    """

    TYPES = [
        'IP',
        'CIDR_BLOCK',
        'URL',
        'EMAIL_ADDRESS',
        'MD5',
        'SHA1',
        'SHA256',
        'MALWARE',
        'SOFTWARE',
        'REGISTRY_KEY',
        'CVE',
        'BITCOIN_ADDRESS',
        'DOMAIN',
        'FQDN',
        'PERSON',
        'LOCATION',
        'ORGANIZATION',
        'DATE',
    ]

    PRIORITY_LEVELS = [
        "NOT_FOUND",
        "LOW",
        "MEDIUM",
        "HIGH"
    ]

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

    def to_dict(self):
        """
        :return: A dictionary representation of the indicator.
        """
        return {
            'value': self.value,
            'type': self.type,
            'priorityLevel': self.priority_level,
            'correlationCount': self.correlation_count
        }

    def __str__(self):
        return json.dumps(self.to_dict())
