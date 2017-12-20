# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# external imports
import json


class ModelBase(object):

    def to_dict(self, remove_nones=False):
        if remove_nones:
            return {k: v for k, v in self.to_dict().items() if v is not None}
        raise NotImplementedError()

    def __str__(self):
        return json.dumps(self.to_dict(remove_nones=True), indent=2)

    def __repr__(self):
        return str(self)
