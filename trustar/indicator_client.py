# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import functools
import json

# package imports
from .log import get_logger
from .models import Indicator, NumberedPage, Tag, IndicatorSummary

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


class IndicatorClient(object):

    def submit_indicators(self, indicators, enclave_ids=None, tags=None):
        """
        Submit indicators directly.  The indicator field ``value`` is required; all other metadata fields are optional:
        ``firstSeen``, ``lastSeen``, ``sightings``, ``notes``, and ``source``. The submission must specify enclaves for
        the indicators to be submitted to, and can optionally specify tags to assign to all the indicators in the
        submission, and/or include individual tags in each Indicator (which will take precedence over the submission tags).
        The tags can be existing or new, and are identified by ``name`` and ``enclaveId``.
        (Passing the GUID of an existing tag is not allowed.  ``name`` and ``enclaveId`` must be specified for each tag.)

        This function uses the API endpoint discussed here:  https://docs.trustar.co/api/v13/indicators/submit_indicators.html
        Note that |Indicator| class attribute names are often slightly different from the API endpoint's parameters.
        (EX: The |Indicator| class's ``first_seen`` attribute corresponds to the API endpoint's ``firstSeen`` parameter.)

        :param list(Indicator) indicators: a list of |Indicator| objects.  Indicator's ``value`` is required, all other
            attributes can be Null.  These |Indicator| attributes can be modified / updated using this function:
            ``value``, ``first_seen``, ``last_seen``, ``sightings``, ``source``, ``notes``, and ``tags``.  No other |Indicator| attributes
            can be modified in TruSTAR by using this function.
        :param list(string) enclave_ids: a list of enclave IDs.
        :param list(Tag) tags: a list of |Tag| objects that will be applied to ALL indicators in the submission.
            All tags' "id" attribute must be None.  All tags' "enclave_id" attribute must contain at least one enclave ID.
        """

        if enclave_ids is None:
            enclave_ids = self.enclave_ids

        tag_guid_msg = ("'id' attribute on all Tag objects in "
                        "submit_indicators(..) method must be None.")
        tag_enclave_id_msg = ("'enclave_id' attribute for all Tag objects in "
                              "submit_indicators(..) method must contain at "
                              "least one enclave ID.")

        # check entire-submission tag for 'id' & 'enclave_id' compliance.
        if tags:
            for tag in tags:
                if tag.id:
                    raise Exception(tag_guid_msg)
                if not tag.enclave_id:
                    raise Exception(tag_enclave_id_msg)

        # check tags on each indicator for 'id' & 'enclave_id' compliance.
        for indicator in indicators:
            if indicator.tags:
                for tag in indicator.tags:
                    if tag.id:
                        raise Exception(tag_guid_msg)
                    if not tag.enclave_id:
                        raise Exception(tag_enclave_id_msg)


        if tags is not None:
            tags = [tag.to_dict() for tag in tags]

        body = {
            "enclaveIds": enclave_ids,
            "content": [indicator.to_dict() for indicator in indicators],
            "tags": tags
        }
        self._client.post("indicators", data=json.dumps(body))

    def get_indicators(self, from_time=None, to_time=None, enclave_ids=None,
                       included_tag_ids=None, excluded_tag_ids=None,
                       start_page=0, page_size=None):
        """
        Creates a generator from the |get_indicators_page| method that returns each successive indicator as an
        |Indicator| object containing values for the 'value' and 'type' attributes only; all
        other |Indicator| object attributes will contain Null values.

        :param int from_time: start of time window in milliseconds since epoch (defaults to 7 days ago).
        :param int to_time: end of time window in milliseconds since epoch (defaults to current time).
        :param list(string) enclave_ids: a list of enclave IDs from which to get indicators from. 
        :param list(string) included_tag_ids: only indicators containing ALL of these tag GUIDs will be returned.
        :param list(string) excluded_tag_ids: only indicators containing NONE of these tags GUIDs be returned. 
        :param int start_page: see 'page_size' explanation.
        :param int page_size: Passing the integer 1000 as the argument to this parameter should result in your script 
        making fewer API calls because it returns the largest quantity of indicators with each API call.  An API call 
        has to be made to fetch each |NumberedPage|.   
        :return: A generator of |Indicator| objects containing values for the "value" and "type" attributes only.
        All other attributes of the |Indicator| object will contain Null values. 
        
        """
        indicators_page_generator = self._get_indicators_page_generator(
            from_time=from_time,
            to_time=to_time,
            enclave_ids=enclave_ids,
            included_tag_ids=included_tag_ids,
            excluded_tag_ids=excluded_tag_ids,
            page_number=start_page,
            page_size=page_size
        )

        indicators_generator = NumberedPage.get_generator(page_generator=indicators_page_generator)

        return indicators_generator

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
        :return: a |NumberedPage| of |Indicator| objects
        """

        get_page = functools.partial(
            self.get_indicators_page,
            from_time=from_time,
            to_time=to_time,
            page_number=page_number,
            page_size=page_size,
            enclave_ids=enclave_ids,
            included_tag_ids=included_tag_ids,
            excluded_tag_ids=excluded_tag_ids
        )
        return NumberedPage.get_page_generator(get_page, page_number, page_size)

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
        :return: a |NumberedPage| of indicators
        """

        params = {
            'from': from_time,
            'to': to_time,
            'pageSize': page_size,
            'pageNumber': page_number,
            'enclaveIds': enclave_ids,
            'tagIds': included_tag_ids,
            'excludedTagIds': excluded_tag_ids
        }

        resp = self._client.get("indicators", params=params)

        page_of_indicators = NumberedPage.from_dict(resp.json(), content_type=Indicator)

        return page_of_indicators

    def search_indicators(self, search_term=None,
                          enclave_ids=None,
                          from_time=None,
                          to_time=None,
                          indicator_types=None,
                          tags=None,
                          excluded_tags=None):
        """
        Uses the |search_indicators_page| method to create a generator that returns each successive indicator.

        :param str search_term: The term to search for.  If empty, no search term will be applied.  Otherwise, must
            be at least 3 characters.
        :param list(str) enclave_ids: list of enclave ids used to restrict indicators to specific enclaves (optional - by
            default indicators from all of user's enclaves are returned)
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param list(str) indicator_types: a list of indicator types to filter by (optional)
        :param list(str) tags: Name (or list of names) of tag(s) to filter indicators by.  Only indicators containing
            ALL of these tags will be returned. (optional)
        :param list(str) excluded_tags: Indicators containing ANY of these tags will be excluded from the results.
        :return: The generator.
        """

        return NumberedPage.get_generator(page_generator=self._search_indicators_page_generator(search_term, enclave_ids,
                                                                                        from_time, to_time,
                                                                                        indicator_types, tags,
                                                                                        excluded_tags))

    def _search_indicators_page_generator(self, search_term=None,
                                          enclave_ids=None,
                                          from_time=None,
                                          to_time=None,
                                          indicator_types=None,
                                          tags=None,
                                          excluded_tags=None,
                                          start_page=0,
                                          page_size=None):
        """
        Creates a generator from the |search_indicators_page| method that returns each successive page.

        :param str search_term: The term to search for.  If empty, no search term will be applied.  Otherwise, must
            be at least 3 characters.
        :param list(str) enclave_ids: list of enclave ids used to restrict indicators to specific enclaves (optional - by
            default indicators from all of user's enclaves are returned)
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param list(str) indicator_types: a list of indicator types to filter by (optional)
        :param list(str) tags: Name (or list of names) of tag(s) to filter indicators by.  Only indicators containing
            ALL of these tags will be returned. (optional)
        :param list(str) excluded_tags: Indicators containing ANY of these tags will be excluded from the results.
        :param int start_page: The page to start on.
        :param page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.search_indicators_page, search_term, enclave_ids,
                                     from_time, to_time, indicator_types, tags, excluded_tags)
        return NumberedPage.get_page_generator(get_page, start_page, page_size)

    def search_indicators_page(self, search_term=None,
                               enclave_ids=None,
                               from_time=None,
                               to_time=None,
                               indicator_types=None,
                               tags=None,
                               excluded_tags=None,
                               page_size=None,
                               page_number=None):
        """
        Search for indicators containing a search term.

        :param str search_term: The term to search for.  If empty, no search term will be applied.  Otherwise, must
            be at least 3 characters.
        :param list(str) enclave_ids: list of enclave ids used to restrict to indicators found in reports in specific
            enclaves (optional - by default reports from all of the user's enclaves are used)
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param list(str) indicator_types: a list of indicator types to filter by (optional)
        :param list(str) tags: Name (or list of names) of tag(s) to filter indicators by.  Only indicators containing
            ALL of these tags will be returned. (optional)
        :param list(str) excluded_tags: Indicators containing ANY of these tags will be excluded from the results.
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: a |NumberedPage| of |Indicator| objects.
        """

        body = {
            'searchTerm': search_term
        }

        params = {
            'enclaveIds': enclave_ids,
            'from': from_time,
            'to': to_time,
            'entityTypes': indicator_types,
            'tags': tags,
            'excludedTags': excluded_tags,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        resp = self._client.post("indicators/search", params=params, data=json.dumps(body))

        return NumberedPage.from_dict(resp.json(), content_type=Indicator)

    def get_related_indicators(self, indicators=None, enclave_ids=None):
        """
        Uses the |get_related_indicators_page| method to create a generator that returns each successive report.

        :param list(string) indicators: list of indicator values to search for
        :param list(string) enclave_ids: list of GUIDs of enclaves to search in
        :return: The generator.
        """

        return NumberedPage.get_generator(page_generator=self._get_related_indicators_page_generator(indicators, enclave_ids))

    def get_indicators_for_report(self, report_id):
        """
        Creates a generator that returns each successive indicator for a given report.

        :param str report_id: The ID of the report to get indicators for.
        :return: The generator.
        """

        return NumberedPage.get_generator(page_generator=self._get_indicators_for_report_page_generator(report_id))

    def get_indicator_metadata(self, value):
        """
        Provide metadata associated with a single indicators, including value, indicatorType, noteCount,
        sightings, lastSeen, enclaveIds, and tags. The metadata is determined based on the enclaves the user making the
        request has READ access to.

        :param value: an indicator value to query.
        :return: A dict containing three fields: 'indicator' (an |Indicator| object), 'tags' (a list of |Tag|
            objects), and 'enclaveIds' (a list of enclave IDs that the indicator was found in).

        .. warning:: This method is deprecated.  Please use |get_indicators_metadata| instead.
        """

        result = self.get_indicators_metadata([Indicator(value=value)])
        if len(result) > 0:
            indicator = result[0]
            return {
                'indicator': indicator,
                'tags': indicator.tags,
                'enclaveIds': indicator.enclave_ids
            }
        else:
            return None

    def get_indicators_metadata(self, indicators, enclave_ids=None):
        """
        Provide metadata associated with an list of indicators, including value, indicatorType, noteCount, sightings,
        lastSeen, enclaveIds, and tags. The metadata is determined based on the enclaves the user making the request has
        READ access to.

        :param indicators: a list of |Indicator| objects to query.  Values are required, types are optional.  Types
            might be required to distinguish in a case where one indicator value has been associated with multiple types
            based on different contexts.
        :param enclave_ids: a list of enclave IDs to restrict to.  By default, uses all of the user's enclaves.
        :return: A list of |Indicator| objects.  The following attributes of the objects will be returned:  
            correlation_count, last_seen, sightings, notes, tags, enclave_ids.  All other attributes of the Indicator
            objects will have Null values.  
        """

        params = {
            'enclaveIds': enclave_ids
        }

        data = [{
            'value': i.value,
            'indicatorType': i.type
        } for i in indicators]

        resp = self._client.post("indicators/metadata", params=params, data=json.dumps(data))

        return [Indicator.from_dict(x) for x in resp.json()]

    def get_indicator_summaries(self, values, enclave_ids=None, start_page=0, page_size=None):
        """
        Creates a generator from the |get_indicator_summaries_page| method that returns each successive indicator
        summary.

        :param list(string) values: A list of indicator values to query.  These must **exactly match** values in the
            TruSTAR system.  In order to perform a fuzzy match, you must first use the |search_indicators| method to lookup
            the exact indicator values, then provide them to this endpoint.
        :param list(string) enclave_ids: The enclaves to search for indicator summaries in.  These should be enclaves
            containing data from sources on the TruSTAR Marketplace.  This parameter is optional, if not provided then
            all of the user's enclaves will be used.
        :param int start_page: the page to start on.
        :param int page_size: the size of the page to be returned.

        :return: A generator of |IndicatorSummary| objects.
        """

        indicator_summaries_page_generator = self._get_indicator_summaries_page_generator(
            values=values,
            enclave_ids=enclave_ids,
            start_page=start_page,
            page_size=page_size
        )

        return NumberedPage.get_generator(page_generator=indicator_summaries_page_generator)

    def _get_indicator_summaries_page_generator(self, values, enclave_ids=None, start_page=0, page_size=None):
        """
        Creates a generator from the |get_indicator_summaries_page| method that returns each successive page.

        :param list(string) values: A list of indicator values to query.  These must **exactly match** values in the
            TruSTAR system.  In order to perform a fuzzy match, you must first use the |search_indicators| method to lookup
            the exact indicator values, then provide them to this endpoint.
        :param list(string) enclave_ids: The enclaves to search for indicator summaries in.  These should be enclaves
            containing data from sources on the TruSTAR Marketplace.
        :param int start_page: the page to start on.
        :param int page_size: the size of the page to be returned.

        :return: A generator of |IndicatorSummary| objects.
        """

        get_page = functools.partial(self.get_indicator_summaries_page, values=values, enclave_ids=enclave_ids)
        return NumberedPage.get_page_generator(get_page, start_page, page_size)

    def get_indicator_summaries_page(self, values, enclave_ids=None, page_number=0, page_size=None):
        """
        Provides structured summaries about indicators, which are derived from intelligence sources on the TruSTAR Marketplace.

        :param list(string) values: A list of indicator values to query.  These must **exactly match** values in the
            TruSTAR system.  In order to perform a fuzzy match, you must first use the |search_indicators| method to lookup
            the exact indicator values, then provide them to this endpoint.
        :param list(string) enclave_ids: The enclaves to search for indicator summaries in.  These should be enclaves
            containing data from sources on the TruSTAR Marketplace.
        :param int page_number: the page to get.
        :param int page_size: the size of the page to be returned.

        :return: A generator of |IndicatorSummary| objects.
        """

        params = {
            'enclaveIds': enclave_ids,
            'pageNumber': page_number,
            'pageSize': page_size
        }

        resp = self._client.post("indicators/summaries", json=values, params=params)

        return NumberedPage.from_dict(resp.json(), IndicatorSummary)

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

    def get_whitelist(self):
        """
        Uses the |get_whitelist_page| method to create a generator that returns each successive whitelisted indicator.

        :return: The generator.
        """

        return NumberedPage.get_generator(page_generator=self._get_whitelist_page_generator())

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

    def get_whitelist_page(self, page_number=None, page_size=None):
        """
        Gets a paginated list of indicators that the user's company has whitelisted.

        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: A |NumberedPage| of |Indicator| objects.
        """

        params = {
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self._client.get("whitelist", params=params)
        return NumberedPage.from_dict(resp.json(), content_type=Indicator)
    
    def get_indicators_for_report_page(self, report_id, page_number=None, page_size=None):
        """
        Get a page of the indicators that were extracted from a report.

        :param str report_id: the ID of the report to get the indicators for
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: A |NumberedPage| of |Indicator| objects.
        """

        params = {
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self._client.get("reports/%s/indicators" % report_id, params=params)
        return NumberedPage.from_dict(resp.json(), content_type=Indicator)

    def get_related_indicators_page(self, indicators=None, enclave_ids=None, page_size=None, page_number=None):
        """
        Finds all reports that contain any of the given indicators and returns correlated indicators from those reports.

        :param indicators: list of indicator values to search for
        :param enclave_ids: list of IDs of enclaves to search in
        :param page_size: number of results per page
        :param page_number: page to start returning results on
        :return: A |NumberedPage| of |Report| objects.
        """

        params = {
            'indicators': indicators,
            'enclaveIds': enclave_ids,
            'pageNumber': page_number,
            'pageSize': page_size
        }

        resp = self._client.get("indicators/related", params=params)

        return NumberedPage.from_dict(resp.json(), content_type=Indicator)

    def _get_indicators_for_report_page_generator(self, report_id, start_page=0, page_size=None):
        """
        Creates a generator from the |get_indicators_for_report_page| method that returns each successive page.

        :param str report_id: The ID of the report to get indicators for.
        :param int start_page: The page to start on.
        :param int page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.get_indicators_for_report_page, report_id=report_id)
        return NumberedPage.get_page_generator(get_page, start_page, page_size)

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
        return NumberedPage.get_page_generator(get_page, start_page, page_size)

    def _get_whitelist_page_generator(self, start_page=0, page_size=None):
        """
        Creates a generator from the |get_whitelist_page| method that returns each successive page.

        :param int start_page: The page to start on.
        :param int page_size: The size of each page.
        :return: The generator.
        """

        return NumberedPage.get_page_generator(self.get_whitelist_page, start_page, page_size)

    def initiate_indicator_metadata_export(self, search_term=None,
                                           enclave_ids=None,
                                           from_time=None,
                                           to_time=None,
                                           indicator_types=None,
                                           tags=None,
                                           excluded_tags=None):
        """
        Initiate a bulk export of indicator metadata

        :param str search_term: The term to search for.  If empty, no search term will be applied.  Otherwise, must
            be at least 3 characters.
        :param list(str) enclave_ids: list of enclave ids used to restrict to indicators found in reports in specific
            enclaves (optional - by default reports from all of the user's enclaves are used)
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param list(str) indicator_types: a list of indicator types to filter by (optional)
        :param list(str) tags: Name (or list of names) of tag(s) to filter indicators by.  Only indicators containing
            ALL of these tags will be returned. (optional)
        :param list(str) excluded_tags: Indicators containing ANY of these tags will be excluded from the results.
        :return: The guid of the export job
        """

        body = {
            'searchTerm': search_term
        }

        params = {
            'enclaveIds': enclave_ids,
            'from': from_time,
            'to': to_time,
            'entityTypes': indicator_types,
            'tags': tags,
            'excludedTags': excluded_tags
        }

        resp = self._client.post("indicators/metadata/bulk-export", params=params, data=json.dumps(body))

        return resp.json().get('guid')

    def get_indicator_metadata_export_status(self, guid):
        """
        Get the status of a currently running indicator metadata export job.  The result will be one of RUNNING,
        ERROR, or COMPLETE

        :param str guid: The guid of the export job
        :return: The status of the export job
        """

        resp = self._client.get("indicators/metadata/bulk-export/" + guid + "/status")

        return resp.json().get('status')

    def download_indicator_metadata_export(self, guid, filename):
        """
        Download the contents of a COMPLETE export job to the file specified by filename

        :param str guid: The guid of the export job
        :param str filename: The name of the file to save the contents
        """

        with self._client.get("indicators/metadata/bulk-export/" + guid + "/data.csv", stream=True) as r:
            r.raise_for_status()
            with open(filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
