# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# external imports
import json


class Enclave:
    """
    Models an enclave.

    :ivar id: The guid of the enclave.
    :ivar name: The name of the enclave.
    """

    def __init__(self, id, name=None):
        """
        Constructs an Enclave object.
        :param id: The guid of the enclave.
        :param name: The name of the enclave.
        """
        self.id = id
        self.name = name

    @staticmethod
    def from_dict(enclave):
        """
        Create a enclave object from a dictionary.
        :param enclave: The dictionary.
        :return: The enclave object.
        """
        return Enclave(id=enclave['id'],
                       name=enclave['name'])

    def to_dict(self):
        """
        :return: A dictionary representation of the enclave.
        """
        d = {'id': self.id}

        if self.name is not None:
            d['name'] = self.name

        return d

    def __str__(self):
        return json.dumps(self.to_dict())
