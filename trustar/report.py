# from .trustar import TruStar
from .utils import normalize_timestamp
import json

DISTRIBUTION_TYPE_ENCLAVE = "ENCLAVE"
DISTRIBUTION_TYPE_COMMUNITY = "COMMUNITY"


class Report(object):

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
                 enclave_ids=None):

        if is_enclave:

            # if string, convert comma-separated list into python list
            if isinstance(enclave_ids, str) or isinstance(enclave_ids, unicode):
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

    def get_distribution_type(self):
        if self.is_enclave:
            return DISTRIBUTION_TYPE_ENCLAVE
        else:
            return DISTRIBUTION_TYPE_COMMUNITY

    def to_dict(self, update=False):
        result = {
            'title': self.title,
            'reportBody': self.body,
            'timeBegan': normalize_timestamp(self.time_began),
            'externalUrl': self.external_url,
            'distributionType': self.get_distribution_type()
        }

        if not update:
            result['externalTrackingId'] = self.external_id

        return result

    @classmethod
    def from_dict(cls, report):

        is_enclave = report.get('distributionType')
        if is_enclave is not None:
            is_enclave = is_enclave.upper() != DISTRIBUTION_TYPE_COMMUNITY

        return Report(
            id=report.get('id'),
            title=report.get('title'),
            body=report.get('reportBody'),
            time_began=report.get('timeBegan'),
            external_url=report.get('externalUrl'),
            is_enclave=is_enclave
        )

    def __str__(self):
        return json.dumps(self.to_dict())
