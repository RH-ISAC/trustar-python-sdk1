# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import functools
import json

# package imports
from .models import Indicator, Page, Tag
from .utils import get_logger

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


class IndicatorClient(object):

    def get_indicators_for_report_page(self, report_id, page_number=None, page_size=None):
        """
        Get a page of the indicators that were extracted from a report.

        :param str report_id: the ID of the report to get the indicators for
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: A |Page| of |Indicator| objects.
        """

        params = {
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self._client.get("reports/%s/indicators" % report_id, params=params)
        return Page.from_dict(resp.json(), content_type=Indicator)

    def get_community_trends(self, indicator_type=None, days_back=None):
        """
        Find indicators that are trending in the community.

        :param indicator_type: A type of indicator to filter by.  If ``None``, will get all types of indicators except
            for MALWARE and CVEs (this convention is for parity with the corresponding view on the Dashboard).
        :param days_back: The number of days back to search.  Any integer between 1 and 30 is allowed.
        :return: A list of |Indicator| objects.
        """

        params = {
            'type': indicator_type,
            'daysBack': days_back
        }

        resp = self._client.get("indicators/community-trending", params=params)
        body = resp.json()

        # parse items in response as indicators
        return [Indicator.from_dict(indicator) for indicator in body]

    def get_related_indicators_page(self, indicators=None, enclave_ids=None, page_size=None, page_number=None):
        """
        Finds all reports that contain any of the given indicators and returns correlated indicators from those reports.

        :param indicators: list of indicator values to search for
        :param enclave_ids: list of IDs of enclaves to search in
        :param page_size: number of results per page
        :param page_number: page to start returning results on
        :return: A |Page| of |Report| objects.
        """

        params = {
            'indicators': indicators,
            'enclaveIds': enclave_ids,
            'pageNumber': page_number,
            'pageSize': page_size
        }

        resp = self._client.get("indicators/related", params=params)

        return Page.from_dict(resp.json(), content_type=Indicator)

    def search_indicators_page(self, search_term, enclave_ids=None, page_size=None, page_number=None):
        """
        Search for indicators containing a search term.

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict to indicators found in reports in specific
            enclaves (optional - by default reports from all of the user's enclaves are used)
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: a |Page| of |Indicator| objects.
        """

        params = {
            'searchTerm': search_term,
            'enclaveIds': enclave_ids,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        resp = self._client.get("indicators/search", params=params)

        return Page.from_dict(resp.json(), content_type=Indicator)

    def submit_indicators(self, indicators, enclave_ids=None, tags=None):
        """
        Submit indicators directly.  Indicator value is required, other metadata is optional: firstSeen, lastSeen,
        sightings, notes, and source. The submission must specify enclaves for the indicators to be submitted to, and
        can optionally specify tags to assign to all the indicators in the submission. The tags can be existing or new,
        and are identified by name and enclaveId.

        :param list(Indicator) indicators: a list of |Indicator| objects.
        :param list(string) enclave_ids: a list of enclave IDs.
        :param list(string) tags: a list of |Tag| objects that will be applied to all indicators in the submission.
        """

        if enclave_ids is None:
            enclave_ids = self.enclave_ids

        body = {
            "enclaveIds": enclave_ids,
            "content": [indicator.to_dict() for indicator in indicators],
            "tags": [tag.to_dict() for tag in tags]
        }
        self._client.post("indicators", data=json.dumps(body))

    def get_indicators_page(self, from_time=None, to_time=None, page_number=None, page_size=None,
                            enclave_ids=None, included_tag_ids=None, excluded_tag_ids=None):
        """
        Get a page of indicators matching the provided filters.

        :param int from_time: start of time window in milliseconds since epoch (defaults to 7 days ago)
        :param int to_time: end of time window in milliseconds since epoch (defaults to current time)
        :param int page_number: the page number
        :param int page_size: the page size
        :param list(string) enclave_ids: a list of enclave IDs to filter by
        :param list(string) included_tag_ids: only indicators containing ALL of these tags will be returned
        :param list(string) excluded_tag_ids: only indicators containing NONE of these tags will be returned
        :return: a |Page| of indicators
        """

        params = {
            'from': from_time,
            'to': to_time,
            'pageSize': page_size,
            'startPage': page_number,
            'enclaveIds': enclave_ids,
            'includedTags': included_tag_ids,
            'excludedTags': excluded_tag_ids
        }

        resp = self._client.get("indicators", params=params)

        return Page.from_dict(resp.json(), content_type=Indicator)

    def get_indicator_metadata(self,value):
        """
        Provide metadata associated with an indicator, including value, indicatorType, noteCount, sightings, lastSeen,
        enclaveIds, and tags. The metadata is determined based on the enclaves the user making the request has READ
        access to.

        :param value: the value of the indicator
        :return: A dict containing three fields: 'indicator' (an |Indicator| object), 'tags' (a list of |Tag| objects),
            and 'enclaveIds' (a list of enclave IDs that the indicator was found in).
        """

        resp = self._client.get("indicators/%s/metadata" % value)
        body = resp.json()

        indicator = Indicator.from_dict(body)
        tags = [Tag.from_dict(tag) for tag in body.get('tags')]
        enclave_ids = body.get('enclaveIds')

        return {
            'indicator': indicator,
            'tags': tags,
            'enclaveIds': enclave_ids
        }

    def get_indicator_details(self, indicators, enclave_ids=None):
        """
        NOTE: This method uses an API endpoint that is intended for internal use only, and is not officially supported.

        Provide a list of indicator values and obtain details for all of them, including indicator_type, priority_level,
        correlation_count, and whether they have been whitelisted.  Note that the values provided must match indicator
        values in Station exactly.  If the exact value of an indicator is not known, it should be obtained either through
        the search endpoint first.

        :param indicators: A list of indicator values of any type.
        :param enclave_ids: Only find details for indicators in these enclaves.

        :return: a list of |Indicator| objects with all fields (except possibly ``reason``) filled out
        """

        # if the indicators parameter is a string, make it a singleton
        if isinstance(indicators, string_types):
            indicators = [indicators]

        params = {
            'enclaveIds': enclave_ids,
            'indicatorValues': indicators
        }
        resp = self._client.get("indicators/details", params=params)

        return [Indicator.from_dict(indicator) for indicator in resp.json()]

    def get_whitelist_page(self, page_number=None, page_size=None):
        """
        Gets a paginated list of indicators that the user's company has whitelisted.

        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: A |Page| of |Indicator| objects.
        """

        params = {
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self._client.get("whitelist", params=params)
        return Page.from_dict(resp.json(), content_type=Indicator)

    def add_terms_to_whitelist(self, terms):
        """
        Add a list of terms to the user's company's whitelist.

        :param terms: The list of terms to whitelist.
        :return: The list of extracted |Indicator| objects that were whitelisted.
        """

        resp = self._client.post("whitelist", json=terms)
        return [Indicator.from_dict(indicator) for indicator in resp.json()]

    def delete_indicator_from_whitelist(self, indicator):
        """
        Delete an indicator from the user's company's whitelist.

        :param indicator: An |Indicator| object, representing the indicator to delete.
        """

        params = indicator.to_dict()
        self._client.delete("whitelist", params=params)

    def _get_indicators_for_report_page_generator(self, report_id, start_page=0, page_size=None):
        """
        Creates a generator from the |get_indicators_for_report_page| method that returns each successive page.

        :param str report_id: The ID of the report to get indicators for.
        :param int start_page: The page to start on.
        :param int page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.get_indicators_for_report_page, report_id=report_id)
        return Page.get_page_generator(get_page, start_page, page_size)

    def get_indicators_for_report(self, report_id):
        """
        Creates a generator that returns each successive indicator for a given report.

        :param str report_id: The ID of the report to get indicators for.
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._get_indicators_for_report_page_generator(report_id))

    def _get_indicators_page_generator(self, from_time=None, to_time=None, page_number=0, page_size=None,
                                       enclave_ids=None, included_tag_ids=None, excluded_tag_ids=None):
        """
        Creates a generator from the |get_indicators_page| method that returns each successive page.

        :param int from_time: start of time window in milliseconds since epoch (defaults to 7 days ago)
        :param int to_time: end of time window in milliseconds since epoch (defaults to current time)
        :param int page_number: the page number
        :param int page_size: the page size
        :param list(string) enclave_ids: a list of enclave IDs to filter by
        :param list(string) included_tag_ids: only indicators containing ALL of these tags will be returned
        :param list(string) excluded_tag_ids: only indicators containing NONE of these tags will be returned
        :return: a |Page| of |Indicator| objects
        """

        get_page = functools.partial(self.get_indicators_page, from_time=from_time, to_time=to_time,
                                     page_number=page_number, page_size=page_size, enclave_ids=enclave_ids,
                                     included_tag_ids=included_tag_ids, excluded_tag_ids=excluded_tag_ids)
        return Page.get_page_generator(get_page, page_number, page_size)

    def get_indicators(self, from_time=None, to_time=None, enclave_ids=None,
                       included_tag_ids=None, excluded_tag_ids=None):
        """
        Creates a generator from the |get_indicators_page| method that returns each successive page.

        :param int from_time: start of time window in milliseconds since epoch (defaults to 7 days ago)
        :param int to_time: end of time window in milliseconds since epoch (defaults to current time)
        :param list(string) enclave_ids: a list of enclave IDs to filter by
        :param list(string) included_tag_ids: only indicators containing ALL of these tags will be returned
        :param list(string) excluded_tag_ids: only indicators containing NONE of these tags will be returned
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._get_indicators_page_generator(from_time=from_time,
                                                                                     to_time=to_time,
                                                                                     enclave_ids=enclave_ids,
                                                                                     included_tag_ids=included_tag_ids,
                                                                                     excluded_tag_ids=excluded_tag_ids))

    def _get_related_indicators_page_generator(self, indicators=None, enclave_ids=None, start_page=0, page_size=None):
        """
        Creates a generator from the |get_related_indicators_page| method that returns each
        successive page.

        :param indicators: list of indicator values to search for
        :param enclave_ids: list of IDs of enclaves to search in
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.get_related_indicators_page, indicators, enclave_ids)
        return Page.get_page_generator(get_page, start_page, page_size)

    def get_related_indicators(self, indicators=None, enclave_ids=None):
        """
        Uses the |get_related_indicators_page| method to create a generator that returns each successive report.

        :param indicators: list of indicator values to search for
        :param enclave_ids: list of IDs of enclaves to search in
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._get_related_indicators_page_generator(indicators, enclave_ids))

    def _get_whitelist_page_generator(self, start_page=0, page_size=None):
        """
        Creates a generator from the |get_whitelist_page| method that returns each successive page.

        :param int start_page: The page to start on.
        :param page_size: The size of each page.
        :return: The generator.
        """

        return Page.get_page_generator(self.get_whitelist_page, start_page, page_size)

    def get_whitelist(self):
        """
        Uses the |get_whitelist_page| method to create a generator that returns each successive whitelisted indicator.

        :return: The generator.
        """

        return Page.get_generator(page_generator=self._get_whitelist_page_generator())

    def _search_indicators_page_generator(self, search_term, enclave_ids=None, start_page=0, page_size=None):
        """
        Creates a generator from the |search_indicators_page| method that returns each successive page.

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict indicators to specific enclaves (optional - by
            default indicators from all of user's enclaves are returned)
        :param int start_page: The page to start on.
        :param page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.search_indicators_page, search_term, enclave_ids)
        return Page.get_page_generator(get_page, start_page, page_size)

    def search_indicators(self, search_term, enclave_ids=None):
        """
        Uses the |search_indicators_page| method to create a generator that returns each successive indicator.

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict indicators to specific enclaves (optional - by
            default indicators from all of user's enclaves are returned)
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._search_indicators_page_generator(search_term, enclave_ids))
