# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, super
from future import standard_library
from six import string_types

# package imports
from ..utils import normalize_timestamp, enclaves_from_ids
from . import Indicator, Enclave
from .base import ModelBase
from .enum import *


class Report(ModelBase):
    """
    Models an incident report.

    :ivar id: the report guid
    :ivar title: the report title
    :ivar body: the report body
    :ivar time_began: the time that the incident began; either an integer (milliseconds since epoch) or an isoformat
        datetime string
    :ivar external_id: An external tracking id.  For instance, if the report is a copy of a corresponding report in some
        external system, this should contain its id in that system.
    :ivar external_url: A URL to the report in an external system (if one exists).
    :ivar is_enclave: A boolean representing whether the distribution type of the report is ENCLAVE or COMMUNITY.
    :ivar enclaves: A list of Enclave objects representing the enclaves that the report belongs to.
    :ivar indicators: A list of Indicator objects representing the indicators extracted from the report.
        Should be None if the report has not yet been submitted.  This property should not be edited directly; it should
        only be set internally, after a report has been submitted or updated.
    """

    ID_TYPE_INTERNAL = IdType.INTERNAL
    ID_TYPE_EXTERNAL = IdType.EXTERNAL

    DISTRIBUTION_TYPE_ENCLAVE = DistributionType.ENCLAVE
    DISTRIBUTION_TYPE_COMMUNITY = DistributionType.COMMUNITY

    def __init__(self,
                 id=None,
                 title=None,
                 body=None,
                 time_began=None,
                 external_id=None,
                 external_url=None,
                 is_enclave=True,
                 enclave_ids=None,
                 enclaves=None,
                 indicators=None):
        """
        Constructs a Report object.

        :param id: the report guid
        :param title: the report title
        :param body: the report body
        :param time_began: the time that the incident began; either an integer (milliseconds since epoch) or an
            isoformat datetime string
        :param external_id: An external tracking id.  For instance, if the report is a copy of a corresponding report in
            some external system, this should contain its id in that system.
        :param external_url: A URL to the report in an external system (if one exists).
        :param is_enclave: A boolean representing whether the distribution type of the report is ENCLAVE or COMMUNITY.
        :param enclave_ids: A list of guids of the enclaves that the report belongs to.  If "enclaves" parameter is not
            used, then Enclave objects will be constructed from this parameter instead.
        :param enclaves: A list of Enclave objects representing the enclaves that the report belongs to.  If this is
            ``None``, and is_enclave is ``True``, then the ``enclave_ids`` parameter should be used.
        :param indicators: A list of Indicator objects that were extracted from the report.  This parameter should only
            be used internally after a report has been submitted or updated.  Users should not directly create a report
            with indicators already attached.
        """

        # if the report belongs to any enclaves, resolve the list of enclave IDs
        if is_enclave:

            # if enclaves is None, expect that enclave_ids is populated.
            # derive Enclave objects from enclave_ids field instead
            if enclaves is None:
                if enclave_ids is None:
                    raise ValueError("If distribution type is ENCLAVE, " +
                                     "must provide either enclaves or enclave_ids value.")
                enclaves = enclaves_from_ids(enclave_ids)

        time_began = normalize_timestamp(time_began)

        self.id = id
        self.title = title
        self.body = body
        self.time_began = time_began
        self.external_id = external_id
        self.external_url = external_url
        self.is_enclave = is_enclave
        self.enclaves = enclaves
        self.indicators = indicators

    def __get_distribution_type(self):
        """
        :return: A string indicating whether the report belongs to an enclave or not.
        """

        if self.is_enclave:
            return self.DISTRIBUTION_TYPE_ENCLAVE
        else:
            return self.DISTRIBUTION_TYPE_COMMUNITY

    def get_enclave_ids(self):
        """
        :return: The IDs of the enclaves if ``enclaves`` is not ``None``, otherwise ``None``.
        """

        if self.enclaves is not None:
            return [enclave.id for enclave in self.enclaves]
        else:
            return None

    def set_enclave_ids(self, enclave_ids):
        """
        Overwrites all of the report's enclaves with a new set of enclaves.

        :param enclave_ids: The IDs of the enclaves.
        """

        self.enclaves = [Enclave(id=id) for id in enclave_ids]

    def to_dict(self, remove_nones=False):
        """
        Creates a dictionary representation of the object.

        :param remove_nones: Whether ``None`` values should be filtered out of the dictionary.  Defaults to ``False``.
        :return: A dictionary representation of the report.
        """

        if remove_nones:
            report_dict = super().to_dict(remove_nones=True)
        else:
            report_dict = {
                'title': self.title,
                'reportBody': self.body,
                'timeBegan': self.time_began,
                'externalUrl': self.external_url,
                'distributionType': self.__get_distribution_type(),
                'externalTrackingId': self.external_id
            }

        # id field might not be present
        if self.id is not None:
            report_dict['id'] = self.id
        else:
            report_dict['id'] = None

        # indicators field might not be present
        if self.indicators is not None:
            report_dict['indicators'] = [indicator.to_dict(remove_nones=remove_nones) for indicator in self.indicators]
        elif not remove_nones:
            self.indicators = None

        # enclaves field might not be present
        if self.enclaves is not None:
            report_dict['enclaves'] = [enclave.to_dict(remove_nones=remove_nones) for enclave in self.enclaves]
        elif not remove_nones:
            report_dict['enclaves'] = None

        return report_dict

    @classmethod
    def from_dict(cls, report):
        """
        Create a report object from a dictionary.  This method is intended for internal use, to construct a
        :class:`Report` object from the body of a response json.  It expects the keys of the dictionary to match those
        of the json that would be found in a response to an API call such as ``GET /report/{id}``.

        :param report: The dictionary.
        :return: The report object.
        """

        # determine distribution type
        distribution_type = report.get('distributionType')
        if distribution_type is not None:
            is_enclave = distribution_type.upper() != cls.DISTRIBUTION_TYPE_COMMUNITY
        else:
            is_enclave = None

        # parse enclaves
        enclaves = []
        if report.get('enclaves') is not None:
            # parse based on type
            for enclave in report.get('enclaves'):
                # enclave is entire EnclaveDto
                if isinstance(enclave, dict):
                    enclaves.append(Enclave.from_dict(enclave))
                # enclave is just an enclave ID
                elif isinstance(enclave, string_types):
                    enclaves.append(Enclave(id=enclave))
                else:
                    raise ValueError("Expected 'enclave' field to hold either a dictionary representation of an enclave"
                                     " or an enclave ID.  Got '%s' instead." % enclave)

        # parse indicators
        indicators = report.get('indicators')
        if indicators is not None:
            indicators = [Indicator.from_dict(indicator) for indicator in indicators]

        return Report(id=report.get('id'),
                      title=report.get('title'),
                      body=report.get('reportBody'),
                      time_began=report.get('timeBegan'),
                      external_id=report.get('externalTrackingId'),
                      external_url=report.get('externalUrl'),
                      is_enclave=is_enclave,
                      enclave_ids=report.get('enclaveIds'),
                      enclaves=enclaves,
                      indicators=indicators)
