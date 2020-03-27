# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import json
from datetime import datetime
import functools
import logging

# package imports
from .models import Page, PhishingIndicator, PhishingSubmission, TriageStatus
from .utils import get_time_based_page_generator, DAY

# python 2 backwards compatibility
standard_library.install_aliases()

logger = logging.getLogger(__name__)


class PhishingTriageClient(object):

    def get_phishing_submissions(self, from_time=None, to_time=None, normalized_triage_score=None,
                                 enclave_ids=None, status=None, cursor=None):
        """
        Fetches all phishing submissions that fit a given criteria.

        :param int from_time: Start of time window in milliseconds since epoch (defaults to 7 days ago)
        :param int to_time: End of time window in milliseconds since epoch (defaults to current time)
        :param list(int) normalized_triage_score: List of desired scores of phishing submission on a scale of 0-3
                                             (default: [3]).
        :param list(string) enclave_ids: List of enclave ids to pull submissions from.
                                         (defaults to all of a user's enclaves).
        :param list(string) status: List of statuses to filter submissions by. Options are 'UNRESOLVED', 'CONFIRMED',
                                    and 'IGNORED'. (default: ['UNRESOLVED']).
        :param string cursor: A Base64-encoded string that contains information on how to retrieve the next page.
                              If a cursor isn't passed, it will default to pageSize: 25, pageNumber: 0
        """

        phishing_submissions_page_generator = self._get_phishing_submissions_page_generator(
            from_time=from_time,
            to_time=to_time,
            normalized_triage_score=normalized_triage_score,
            enclave_ids=enclave_ids,
            status=status,
            cursor=cursor
        )

        phishing_submissions_generator = Page.get_generator(page_generator=phishing_submissions_page_generator)

        return phishing_submissions_generator

    def _get_phishing_submissions_page_generator(self, from_time=None, to_time=None, normalized_triage_score=None,
                                                 enclave_ids=None, status=None, cursor=None):
        """
        Creates a generator from the |get_indicators_page| method that returns each successive page.

        :param int from_time: Start of time window in milliseconds since epoch (defaults to 7 days ago).
        :param int to_time: End of time window in milliseconds since epoch (defaults to current time).
        :param list(int) normalized_triage_score: List of desired scores of phishing submission on a scale of 0-3
                                                  (default: [3]).
        :param list(string) enclave_ids: A list of enclave IDs to filter by.
        :param list(string) status: List of statuses to filter submissions by. Options are 'UNRESOLVED', 'CONFIRMED',
                                    and 'IGNORED'. (default: ['UNRESOLVED']).
        :param string cursor: A Base64-encoded string that contains information on how to retrieve the next page.
                              If a cursor isn't passed, it will default to pageSize: 25, pageNumber: 0
        """

        def get_next_cursor(result):
            """

            """

            return result.responseMetaData.nextCursor

        get_page = functools.partial(
            self.get_phishing_submissions_page,
            from_time=from_time,
            to_time=to_time,
            normalized_triage_score=normalized_triage_score,
            enclave_ids=enclave_ids,
            status=status,
            cursor=cursor
        )

        return Page.get_cursor_based_page_generator(get_page, get_next_cursor, cursor)

    def get_phishing_submissions_page(self, from_time=None, to_time=None, normalized_triage_score=None,
                                      enclave_ids=None, status=None, cursor=None):
        """
        Get a page of phishing submissions that match the given criteria.

        :param int from_time: Start of time window in milliseconds since epoch (defaults to 7 days ago).
        :param int to_time: End of time window in milliseconds since epoch (defaults to current time).
        :param: int page_number: The page number.
        :param int page_size: The page size.
        :param list(int) normalized_triage_score: List of desired scores of phishing submission on a scale of 0-3
                                             (default: [3]).
        :param list(string) enclave_ids: A list of enclave IDs to filter by.
        :param list(string) status: List of statuses to filter submissions by. Options are 'UNRESOLVED', 'CONFIRMED',
                                    and 'IGNORED'. (default: ['UNRESOLVED']).
        :param string cursor: A Base64-encoded string that contains information on how to retrieve the next page.
                              If a cursor isn't passed, it will default to pageSize: 25, pageNumber: 0
        """

        params = {
            'from': from_time,
            'to': to_time,
            'normalizedTriageScore': normalized_triage_score,
            'enclaveIds': enclave_ids,
            'status': status,
            'cursor': cursor
        }

        resp = self._client.post("triage/submissions", params=params)

        page_of_phishing_submissions = Page.from_dict(resp.json(), content_type=PhishingSubmission)

        return page_of_phishing_submissions

    def mark_triage_status(self):
        pass

    def get_phishing_indicators(self):
        pass
