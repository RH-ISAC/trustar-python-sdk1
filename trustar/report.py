# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

from .utils import normalize_timestamp
import json

DISTRIBUTION_TYPE_ENCLAVE = "ENCLAVE"
DISTRIBUTION_TYPE_COMMUNITY = "COMMUNITY"


class Report(object):
    """
    Models an incident report.
    """

    ID_TYPE_INTERNAL = "INTERNAL"
    ID_TYPE_EXTERNAL = "EXTERNAL"

    def __init__(self,
                 id=None,
                 title=None,
                 body=None,
                 time_began=None,
                 external_id=None,
                 external_url=None,
                 is_enclave=True,
                 enclave_ids=None,
                 indicators=None):

        # if the report belongs to any enclaves, resolve the list of enclave IDs
        if is_enclave:

            # if string, convert comma-separated list into python list
            if isinstance(enclave_ids, string_types):
                enclave_ids = [x.strip() for x in enclave_ids.split(',')]

            # ensure is list
            if not isinstance(enclave_ids, list):
                raise ValueError("Enclave IDs must either be a list or a comma-separated string.")

            # ensure non-empty
            if len(enclave_ids) == 0:
                raise ValueError("Enclave report must have one or more enclave IDs.")

            # filter out None values
            enclave_ids = [i for i in enclave_ids if i is not None]

        self.id = id
        self.title = title
        self.body = body
        self.time_began = time_began
        self.external_id = external_id
        self.external_url = external_url
        self.is_enclave = is_enclave
        self.enclave_ids = enclave_ids
        self.indicators = indicators

    def get_distribution_type(self):
        """
        :return: A string indicating whether the report belongs to an enclave or not.
        """
        if self.is_enclave:
            return DISTRIBUTION_TYPE_ENCLAVE
        else:
            return DISTRIBUTION_TYPE_COMMUNITY

    def to_dict(self):
        """
        :return: A dictionary representation of the report.
        """
        report_dict = {
            'title': self.title,
            'reportBody': self.body,
            'timeBegan': normalize_timestamp(self.time_began),
            'externalUrl': self.external_url,
            'distributionType': self.get_distribution_type(),
            'externalTrackingId': self.external_id
        }

        if self.indicators is not None:
            report_dict['indicators'] = self.indicators

        return report_dict

    @classmethod
    def from_dict(cls, report):

        is_enclave = report.get('distributionType')
        if is_enclave is not None:
            is_enclave = is_enclave.upper() != DISTRIBUTION_TYPE_COMMUNITY

        enclaves = report.get('enclaves')
        if enclaves is not None:
            enclave_ids = [enclave['id'] for enclave in enclaves]
        else:
            enclave_ids = None

        return Report(
            id=report.get('id'),
            title=report.get('title'),
            body=report.get('reportBody'),
            time_began=report.get('timeBegan'),
            external_url=report.get('externalUrl'),
            is_enclave=is_enclave,
            enclave_ids=enclave_ids,
            indicators=report.get('indicators')
        )

    def __str__(self):
        return json.dumps(self.to_dict())
