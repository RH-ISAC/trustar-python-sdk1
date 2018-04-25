# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library
from six import string_types

from .base import ModelBase


class RequestQuota(ModelBase):

    def __init__(self, guid, max_requests, used_requests, time_window, last_reset_time):

        self.guid = guid
        self.max_requests = max_requests
        self.used_requests = used_requests
        self.time_window = time_window
        self.last_reset_time = last_reset_time

    def to_dict(self, remove_nones=False):

        if remove_nones:
            return super().to_dict(remove_nones=True)

        d = {
            'guid': self.guid,
            'maxRequests': self.max_requests,
            'usedRequests': self.used_requests,
            'timeWindow': self.time_window,
            'lastResetTime': self.last_reset_time
        }
        return d

    @classmethod
    def from_dict(cls, d):

        if d is None:
            return None

        return RequestQuota(guid=d.get('guid'),
                            max_requests=d.get('maxRequests'),
                            used_requests=d.get('usedRequests'),
                            time_window=d.get('timeWindow'),
                            last_reset_time=d.get('lastResetTime'))
