# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import json
from datetime import datetime
import functools

# package imports
from .models import Page, Report, DistributionType, IdType
from .utils import get_logger, get_time_based_page_generator

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


class ReportClient(object):

    def get_report_details(self, report_id, id_type=None):
        """
        Retrieves a report by its ID.  Internal and external IDs are both allowed.

        :param str report_id: The ID of the incident report.
        :param str id_type: Indicates whether ID is internal or external.

        :return: The retrieved |Report| object.

        Example:

        >>> report = ts.get_report_details("1a09f14b-ef8c-443f-b082-9643071c522a")
        >>> print(report)
        {
          "id": "1a09f14b-ef8c-443f-b082-9643071c522a",
          "created": 1515571633505,
          "updated": 1515620420062,
          "reportBody": "Employee reported suspect email.  We had multiple reports of suspicious email overnight ...",
          "title": "Phishing Incident",
          "enclaveIds": [
            "ac6a0d17-7350-4410-bc57-9699521db992"
          ],
          "distributionType": "ENCLAVE",
          "timeBegan": 1479941278000
        }

        """

        params = {'idType': id_type}
        resp = self._client.get("reports/%s" % report_id, params=params)
        return Report.from_dict(resp.json())

    def get_reports_page(self, is_enclave=None, enclave_ids=None, tag=None, excluded_tags=None,
                         from_time=None, to_time=None):
        """
        Retrieves a page of reports, filtering by time window, distribution type, enclave association, and tag.
        The results are sorted by updated time.
        This method does not take ``page_number`` and ``page_size`` parameters.  Instead, each successive page must be
        found by adjusting the ``from_time`` and ``to_time`` parameters.

        Note:  This endpoint will only return reports from a time window of maximum size of 2 weeks. If you give a
        time window larger than 2 weeks, it will pull reports starting at 2 weeks before the “to” date, through the
        “to” date.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :param list(str) tag: Name (or list of names) of tag(s) to filter reports by.  Only reports containing
            ALL of these tags will be returned.
        :param list(str) excluded_tags: Reports containing ANY of these tags will be excluded from the results.
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)

        :return: A |Page| of |Report| objects.

        """

        distribution_type = None

        # explicitly compare to True and False to distinguish from None (which is treated as False in a conditional)
        if is_enclave:
            distribution_type = DistributionType.ENCLAVE
        elif not is_enclave:
            distribution_type = DistributionType.COMMUNITY

        if enclave_ids is None:
            enclave_ids = self.enclave_ids

        params = {
            'from': from_time,
            'to': to_time,
            'distributionType': distribution_type,
            'enclaveIds': enclave_ids,
            'tags': tag,
            'excludedTags': excluded_tags
        }
        resp = self._client.get("reports", params=params)
        result = Page.from_dict(resp.json(), content_type=Report)

        # create a Page object from the dict
        return result

    def submit_report(self, report):
        """
        Submits a report.

        * If ``report.is_enclave`` is ``True``, then the report will be submitted to the enclaves
          identified by ``report.enclaves``; if that field is ``None``, then the enclave IDs registered with this
          |TruStar| object will be used.
        * If ``report.time_began`` is ``None``, then the current time will be used.

        :param report: The |Report| object that was submitted, with the ``id`` field updated based
            on values from the response.

        Example:

        >>> report = Report(title="Suspicious Activity",
        >>>                 body="We have been receiving suspicious requests from 169.178.68.63.",
        >>>                 enclave_ids=["602d4795-31cd-44f9-a85d-f33cb869145a"])
        >>> report = ts.submit_report(report)
        >>> print(report.id)
        ac6a0d17-7350-4410-bc57-9699521db992
        >>> print(report.title)
        Suspicious Activity
        """

        # make distribution type default to "enclave"
        if report.is_enclave is None:
            report.is_enclave = True

        if report.enclave_ids is None:
            # use configured enclave_ids by default if distribution type is ENCLAVE
            if report.is_enclave:
                report.enclave_ids = self.enclave_ids
            # if distribution type is COMMUNITY, API still expects non-null list of enclaves
            else:
                report.enclave_ids = []

        if report.is_enclave and len(report.enclave_ids) == 0:
            raise Exception("Cannot submit a report of distribution type 'ENCLAVE' with an empty set of enclaves.")

        # default time began is current time
        if report.time_began is None:
            report.time_began = datetime.now()

        data = json.dumps(report.to_dict())
        resp = self._client.post("reports", data=data, timeout=60)

        # get report id from response body
        report_id = resp.content

        if isinstance(report_id, bytes):
            report_id = report_id.decode('utf-8')

        report.id = report_id

        return report

    def update_report(self, report):
        """
        Updates the report identified by the ``report.id`` field; if this field does not exist, then
        ``report.external_id`` will be used if it exists.  Any other fields on ``report`` that are not ``None``
        will overwrite values on the report in TruSTAR's system.   Any fields that are  ``None`` will simply be ignored;
        their values will be unchanged.

        :param report: A |Report| object with the updated values.
        :return: The |Report| object.

        Example:

        >>> report = ts.get_report_details(report_id)
        >>> print(report.title)
        Old Title
        >>> report.title = "Changed title"
        >>> updated_report = ts.update_report(report)
        >>> print(updated_report.title)
        Changed Title
        """

        # default to interal ID type if ID field is present
        if report.id is not None:
            id_type = IdType.INTERNAL
            report_id = report.id
        # if no ID field is present, but external ID field is, default to external ID type
        elif report.external_id is not None:
            id_type = IdType.EXTERNAL
            report_id = report.external_id
        # if no ID fields exist, raise exception
        else:
            raise Exception("Cannot update report without either an ID or an external ID.")

        # not allowed to update value of 'reportId', so remove it
        report_dict = {k: v for k, v in report.to_dict().items() if k != 'reportId'}

        params = {'idType': id_type}

        data = json.dumps(report.to_dict())
        self._client.put("reports/%s" % report_id, data=data, params=params)

        return report

    def delete_report(self, report_id, id_type=None):
        """
        Deletes the report with the given ID.

        :param report_id: the ID of the report to delete
        :param id_type: indicates whether the ID is internal or an external ID provided by the user
        :return: the response object

        Example:

        >>> response = ts.delete_report("4d1fcaee-5009-4620-b239-2b22c3992b80")
        """

        params = {'idType': id_type}
        self._client.delete("reports/%s" % report_id, params=params)

    def get_correlated_report_ids(self, indicators):
        """
        DEPRECATED!
        Retrieves a list of the IDs of all TruSTAR reports that contain the searched indicators.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :return: The list of IDs of reports that correlated.

        Example:

        >>> report_ids = ts.get_correlated_report_ids(["wannacry", "www.evil.com"])
        >>> print(report_ids)
        ["e3bc6921-e2c8-42eb-829e-eea8da2d3f36", "4d04804f-ff82-4a0b-8586-c42aef2f6f73"]
        """

        params = {'indicators': indicators}
        resp = self._client.get("reports/correlate", params=params)
        return resp.json()

    def get_correlated_reports_page(self, indicators, enclave_ids=None, is_enclave=True,
                                    page_size=None, page_number=None):
        """
        Retrieves a page of all TruSTAR reports that contain the searched indicators.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :param enclave_ids: The enclaves to search in.
        :param is_enclave: Whether to search enclave reports or community reports.
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: The list of IDs of reports that correlated.

        Example:

        >>> reports = ts.get_correlated_reports_page(["wannacry", "www.evil.com"]).items
        >>> print([report.id for report in reports])
        ["e3bc6921-e2c8-42eb-829e-eea8da2d3f36", "4d04804f-ff82-4a0b-8586-c42aef2f6f73"]
        """

        if is_enclave:
            distribution_type = DistributionType.ENCLAVE
        else:
            distribution_type = DistributionType.COMMUNITY

        params = {
            'indicators': indicators,
            'enclaveIds': enclave_ids,
            'distributionType': distribution_type,
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self._client.get("reports/correlated", params=params)

        return Page.from_dict(resp.json(), content_type=Report)

    def search_reports_page(self, search_term, enclave_ids=None, page_size=None, page_number=None):
        """
        Search for reports containing a search term.

        :param str search_term: The term to search for.  This string must be minimum 3 characters in length.
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: a |Page| of |Report| objects.  *NOTE*:  The bodies of these reports will be ``None``.
        """

        params = {
            'searchTerm': search_term,
            'enclaveIds': enclave_ids,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        resp = self._client.get("reports/search", params=params)
        page = Page.from_dict(resp.json(), content_type=Report)

        return page

    def _get_reports_page_generator(self, is_enclave=None, enclave_ids=None, tag=None, excluded_tags=None,
                                    from_time=None, to_time=None):
        """
        Creates a generator from the |get_reports_page| method that returns each successive page.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param str tag: name of tag to filter reports by.  if a tag with this name exists in more than one enclave
            indicated in ``enclave_ids``, the request will fail.  handle this by making separate requests for each
            enclave ID if necessary.
        :param int from_time: start of time window in milliseconds since epoch
        :param int to_time: end of time window in milliseconds since epoch (optional, defaults to current time)
        :return: The generator.
        """

        get_page = functools.partial(self.get_reports_page, is_enclave, enclave_ids, tag, excluded_tags)
        return get_time_based_page_generator(
            get_page=get_page,
            get_next_to_time=lambda x: x.items[-1].updated if len(x.items) > 0 else None,
            from_time=from_time,
            to_time=to_time
        )

    def get_reports(self, is_enclave=None, enclave_ids=None, tag=None, excluded_tags=None, from_time=None, to_time=None):
        """
        Uses the |get_reports_page| method to create a generator that returns each successive report as a trustar
        report object.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param list(str) tag: a list of tags; only reports containing ALL of these tags will be returned. 
            If a tag with this name exists in more than one enclave in the list passed as the ``enclave_ids``
            argument, the request will fail.  Handle this by making separate requests for each
            enclave ID if necessary.
        :param list(str) excluded_tags: a list of tags; reports containing ANY of these tags will not be returned. 
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :return: A generator of Report objects.

        Note:  If a report contains all of the tags in the list passed as argument to the 'tag' parameter and also 
        contains any (1 or more) of the tags in the list passed as argument to the 'excluded_tags' parameter, that 
        report will not be returned by this function.  
        
        Example:

        >>> page = ts.get_reports(is_enclave=True, tag="malicious", from_time=1425695711000, to_time=1514185311000)
        >>> for report in reports: print(report.id)
        '661583cb-a6a7-4cbd-8a90-01578fa4da89'
        'da131660-2708-4c8a-926e-f91fb5dbbc62'
        '2e3400d6-fa37-4a8c-bc2f-155aaa02ae5a'
        '38064828-d3db-4fff-8ab8-e0e3b304ff44'
        'dbf26104-cee5-4ca4-bdbf-a01d0178c007'

        """

        return Page.get_generator(page_generator=self._get_reports_page_generator(is_enclave, enclave_ids, tag,
                                                                                  excluded_tags, from_time, to_time))
    
    def _get_correlated_reports_page_generator(self, indicators, enclave_ids=None, is_enclave=True,
                                               start_page=0, page_size=None):
        """
        Creates a generator from the |get_correlated_reports_page| method that returns each
        successive page.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :param enclave_ids:
        :param is_enclave:
        :return: The generator.
        """

        get_page = functools.partial(self.get_correlated_reports_page, indicators, enclave_ids, is_enclave)
        return Page.get_page_generator(get_page, start_page, page_size)

    def get_correlated_reports(self, indicators, enclave_ids=None, is_enclave=True):
        """
        Uses the |get_correlated_reports_page| method to create a generator that returns each successive report.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :param enclave_ids: The enclaves to search in.
        :param is_enclave: Whether to search enclave reports or community reports.
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._get_correlated_reports_page_generator(indicators,
                                                                                             enclave_ids,
                                                                                             is_enclave))
    
    def _search_reports_page_generator(self, search_term, enclave_ids=None, start_page=0, page_size=None):
        """
        Creates a generator from the |search_reports_page| method that returns each successive page.

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :param int start_page: The page to start on.
        :param page_size: The size of each page.
        :return: The generator.
        """

        get_page = functools.partial(self.search_reports_page, search_term, enclave_ids)
        return Page.get_page_generator(get_page, start_page, page_size)

    def search_reports(self, search_term, enclave_ids=None):
        """
        Uses the |search_reports_page| method to create a generator that returns each successive report.

        :param str search_term: The term to search for.  This string must be at least 3 characters in length.
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :return: The generator of Report objects.  Note that the body attributes of these reports will be ``None``.
        """

        return Page.get_generator(page_generator=self._search_reports_page_generator(search_term, enclave_ids))
