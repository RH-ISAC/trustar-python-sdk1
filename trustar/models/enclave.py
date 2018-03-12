# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library
from six import string_types

# package imports
from .base import ModelBase
from .enum import EnclaveType


class Enclave(ModelBase):
    """
    Models an enclave.

    :ivar id: The guid of the enclave.
    :ivar name: The name of the enclave.
    """

    def __init__(self, id, name=None, type=None):
        """
        Constructs an Enclave object.

        :param id: The guid of the enclave.
        :param name: The name of the enclave.
        :param type: The type of enclave.
        """

        self.id = id
        self.name = name
        self.type = type

    @staticmethod
    def from_dict(enclave):
        """
        Create a enclave object from a dictionary.

        :param enclave: The dictionary.
        :return: The enclave object.
        """

        return Enclave(id=enclave['id'],
                       name=enclave['name'],
                       type=EnclaveType.from_string(enclave['type']))

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
            'name': self.name,
            'type': self.type
        }


class EnclavePermissions(Enclave):

    def __init__(self, id, name=None, type=None, read=None, create=None, update=None):
        """
        Constructs an EnclavePermissions object.

        :param id: The guid of the enclave.
        :param name: The name of the enclave.
        :param type: The type of enclave.
        :param read: Whether the associated user/company has read access.
        :param create: Whether the associated user/company has create access.
        :param update: Whether the associated user/company has update access.
        """

        super().__init__(id, name, type)
        self.read = read
        self.create = create
        self.update = update

    @staticmethod
    def from_dict(enclave):
        """
        Create a enclave object from a dictionary.

        :param enclave: The dictionary.
        :return: The enclave object.
        """

        return Enclave(id=enclave['id'],
                       name=enclave['name'],
                       type=EnclaveType.from_string(enclave['type']))

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
            'name': self.name,
            'type': self.type
        }

    @classmethod
    def from_enclave(cls, enclave):
        """
        Create an |EnclavePermissions| object from an |Enclave| object.

        :param enclave: the Enclave object
        :return: an EnclavePermissions object
        """

        return EnclavePermissions(id=enclave.id,
                                  name=enclave.name,
                                  type=enclave.type)
