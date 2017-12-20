# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# package imports
from ..utils import enclaves_from_ids

# external imports
import json


class Tag:
    """
    Models a tag.

    :ivar name: The name of the tag, i.e. "malicious".
    :ivar id: The ID of the tag.
    :ivar enclave: The :class:`Enclave` object representing the enclave that the tag belongs to.
    """

    def __init__(self, name, id=None, enclave=None, enclave_id=None):
        """
        Constructs a tag object.

        :param name: The name of the tag, i.e. "malicious".
        :param id: The ID of the tag.
        :param enclave: The :class:`Enclave` object representing the enclave that the tag belongs to.
        :param enclave_id: The ID of the enclave the tag belongs to.  This should only be used if the ``enclave``
            parameter is ``None``, in which case this will be used to create the :class:`Enclave` object.
        """

        self.name = name
        self.id = id

        if enclave is None:
            if enclave_id is not None:
                enclaves = enclaves_from_ids([enclave_id])
                enclave = enclaves[0] if enclaves is not None else None
            else:
                enclave = None

        self.enclave = enclave

    @staticmethod
    def from_dict(tag):
        """
        Create a tag object from a dictionary.  This method is intended for internal use, to construct a
        :class:`Tag` object from the body of a response json.  It expects the keys of the dictionary to match those
        of the json that would be found in a response to an API call such as ``GET /enclave-tags``.

        :param tag: The dictionary.
        :return: The :class:`Tag` object.
        """

        return Tag(name=tag.get('name'),
                   id=tag.get('guid'),
                   enclave=tag.get('enclave'),
                   enclave_id=tag.get('enclaveId'))

    def to_dict(self):
        """
        :return: A dictionary representation of the tag.
        """

        return {
            'name': self.name,
            'id': self.id,
            'enclave': self.enclave.to_dict()
        }

    def __str__(self):
        return json.dumps(self.to_dict())
