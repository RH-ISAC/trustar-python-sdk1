# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# package imports
from ..utils import normalize_timestamp, enclaves_from_ids
from . import Indicator, Enclave

# external imports
import json

DISTRIBUTION_TYPE_ENCLAVE = "ENCLAVE"
DISTRIBUTION_TYPE_COMMUNITY = "COMMUNITY"


class Report(object):
    """
    Models an incident report.
    """

    ID_TYPE_INTERNAL = "internal"
    ID_TYPE_EXTERNAL = "external"

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

        # if the report belongs to any enclaves, resolve the list of enclave IDs
        if is_enclave:

            # if enclaves is None, expect that enclave_ids is populated.
            # derive Enclave objects from enclave_ids field instead
            if enclaves is None:
                if enclave_ids is None:
                    raise ValueError("If distribution type is ENCLAVE, " +
                                     "must provide either enclaves or enclave_ids value.")
                enclaves = enclaves_from_ids(enclave_ids)

            # ensure non-empty
            if len(enclaves) == 0:
                raise ValueError("Enclave report must have one or more enclaves.")

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

    def get_distribution_type(self):
        """
        :return: A string indicating whether the report belongs to an enclave or not.
        """
        if self.is_enclave:
            return DISTRIBUTION_TYPE_ENCLAVE
        else:
            return DISTRIBUTION_TYPE_COMMUNITY

    def get_enclave_ids(self):
        """
        :return: Enclave ids if enclaves is not None, else None.
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

    def to_dict(self):
        """
        :return: A dictionary representation of the report.
        """
        report_dict = {
            'title': self.title,
            'reportBody': self.body,
            'timeBegan': self.time_began,
            'externalUrl': self.external_url,
            'distributionType': self.get_distribution_type(),
            'externalTrackingId': self.external_id
        }

        # indicators field might not be present
        if self.indicators is not None:
            report_dict['indicators'] = [indicator.to_dict() for indicator in self.indicators]

        # enclaves field might not be present
        if self.enclaves is not None:
            report_dict['enclaves'] = [enclave.to_dict() for enclave in self.enclaves]

        return report_dict

    @staticmethod
    def from_dict(report):
        """
        Create a report object from a dictionary.
        :param report: The dictionary.
        :return: The report object.
        """

        # determine distribution type
        distribution_type = report.get('distributionType')
        if distribution_type is not None:
            is_enclave = distribution_type.upper() != DISTRIBUTION_TYPE_COMMUNITY
        else:
            is_enclave = None

        # parse enclaves
        enclaves = report.get('enclaves')
        if enclaves is not None:
            enclaves = [Enclave.from_dict(enclave) for enclave in enclaves]

        # parse indicators
        indicators = report.get('indicators')
        if indicators is not None:
            indicators = [Indicator.from_dict(indicator) for indicator in indicators]

        return Report(
            id=report.get('id'),
            title=report.get('title'),
            body=report.get('reportBody'),
            time_began=report.get('timeBegan'),
            external_url=report.get('externalUrl'),
            is_enclave=is_enclave,
            enclave_ids=report.get('enclaveIds'),
            enclaves=enclaves,
            indicators=indicators
        )

    def __str__(self):
        return json.dumps(self.to_dict())
