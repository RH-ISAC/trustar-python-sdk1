# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library
from six import string_types

# package imports
from .base import ModelBase


class Enclave(ModelBase):
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

    def to_dict(self, remove_nones=False):
        """
        Creates a dictionary representation of the enclave.

        :param remove_nones: Whether ``None`` values should be filtered out of the dictionary.  Defaults to ``False``.
        :return: A dictionary representation of the enclave.
        """

        if remove_nones:
            return super().to_dict(remove_nones=True)

        return {
            'id': self.id,
            'name': self.name
        }
