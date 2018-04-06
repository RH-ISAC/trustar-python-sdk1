# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# package imports
from .models import Tag
from .utils import get_logger

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


class TagClient(object):
    
    def get_enclave_tags(self, report_id, id_type=None):
        """
        Retrieves all enclave tags present in a specific report.

        :param report_id: the ID of the report
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :return: A list of  |Tag| objects.
        """

        params = {'idType': id_type}
        resp = self._client.get("reports/%s/tags" % report_id, params=params)
        return [Tag.from_dict(indicator) for indicator in resp.json()]

    def add_enclave_tag(self, report_id, name, enclave_id, id_type=None):
        """
        Adds a tag to a specific report, for a specific enclave.

        :param report_id: The ID of the report
        :param name: The name of the tag to be added
        :param enclave_id: ID of the enclave where the tag will be added
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :return: A |Tag| object representing the tag that was created.
        """

        params = {
            'idType': id_type,
            'name': name,
            'enclaveId': enclave_id
        }
        resp = self._client.post("reports/%s/tags" % report_id, params=params)
        return str(resp.content)

    def delete_enclave_tag(self, report_id, tag_id, id_type=None):
        """
        Deletes a tag from a specific report, in a specific enclave.

        :param report_id: The ID of the report
        :param tag_id: ID of the tag to delete
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :return: The response body.
        """

        params = {
            'idType': id_type
        }
        self._client.delete("reports/%s/tags/%s" % (report_id, tag_id), params=params)

    def get_all_enclave_tags(self, enclave_ids=None):
        """
        Retrieves all tags present in the given enclaves. If the enclave list is empty, the tags returned include all
        tags for all enclaves the user has access to.

        :param enclave_ids: list of enclave IDs
        :return: The list of |Tag| objects.
        """

        params = {'enclaveIds': enclave_ids}
        resp = self._client.get("reports/tags", params=params)
        return [Tag.from_dict(indicator) for indicator in resp.json()]