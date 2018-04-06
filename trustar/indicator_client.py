# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import functools

# package imports
from .models import Indicator, Page
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
        :param days_back: The number of days back to search.  Allowed values: 1, 3, 7, 30
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
