from __future__ import print_function

import json
import time
from datetime import datetime

import configparser
import dateutil.parser
import pytz
import math
import requests
import requests.auth
from builtins import object
from future import standard_library
from tzlocal import get_localzone
from requests import HTTPError\

standard_library.install_aliases()

CLIENT_VERSION = "0.3.0"

DISTRIBUTION_TYPE_ENCLAVE = "ENCLAVE"
DISTRIBUTION_TYPE_COMMUNITY = "COMMUNITY"


class TruStar(object):
    """
    Main class you to instantiate the TruStar API
    """

    REQUIRED_KEYS = ['auth', 'base', 'api_key', 'api_secret']
    DEFAULTS = {
        'client_type': 'PYTHON_SDK',
        'client_version': CLIENT_VERSION,
        'client_metatag': None,
        'verify': True
    }

    def __init__(self, config_file="../examples/trustar.conf", config_role="trustar", config=None):

        # attempt to use configuration file if one exists
        if config is None:

            if config is not None:
                raise Exception("Cannot use 'config' parameter if also using 'config_file' parameter.")

            config_parser = configparser.RawConfigParser()
            config_parser.read(config_file)

            try:
                # parse enclaves
                if config_parser.has_option(config_role, 'enclave_ids'):
                    enclave_ids = config_parser.get(config_role, 'enclave_ids').split(',')
                else:
                    enclave_ids = []

                # use config file to create config dict
                config = {
                    'auth': config_parser.get(config_role, 'auth_endpoint'),
                    'base': config_parser.get(config_role, 'api_endpoint'),
                    'api_key': config_parser.get(config_role, 'user_api_key'),
                    'api_secret': config_parser.get(config_role, 'user_api_secret'),
                    'client_type': config_parser.get(config_role, 'client_type', fallback=None),
                    'client_version': config_parser.get(config_role, 'client_version', fallback=None),
                    'client_metatag': config_parser.get(config_role, 'client_metatag', fallback=None),
                    'verify': config_parser.get(config_role, 'verify', fallback=None),
                    'enclave_ids': [x.strip() for x in enclave_ids if x is not None]
                }

            except Exception as e:
                raise KeyError("Problem reading config file: %s" % e)

        # set properties from config dict
        for key, val in config.items():
            if val is None:
                # ensure required properties are present
                if val in TruStar.REQUIRED_KEYS:
                    raise Exception("Missing config value for %s" % key)
                elif val in TruStar.DEFAULTS:
                    config[key] = TruStar.DEFAULTS[key]

        # set properties
        self.auth = config['auth']
        self.base = config['base']
        self.api_key = config['api_key']
        self.api_secret = config['api_secret']
        self.client_type = config['client_type']
        self.client_version = config['client_version']
        self.client_metatag = config['client_metatag']
        self.verify = config['verify']
        self.enclave_ids = config['enclave_ids']


    @staticmethod
    def normalize_timestamp(date_time):
        """
        Attempt to convert a string timestamp in to a TruSTAR compatible format for submission.
        Will return current time with UTC time zone if None
        :param date_time: int that is epoch time, or string/datetime object containing date, time, and ideally timezone
        examples of supported timestamp formats: 1487890914, 1487890914000, "2017-02-23T23:01:54", "2017-02-23T23:01:54+0000"
        """
        datetime_dt = datetime.now()

        # get current time in seconds-since-epoch
        current_time = int(time.time())

        try:
            # identify type of timestamp and convert to datetime object
            if isinstance(date_time, int):

                # if timestamp has more than 10 digits, it is in ms
                if date_time > 9999999999:
                    date_time /= 1000

                # if timestamp is incorrectly forward dated, set to current time
                if date_time > current_time:
                    date_time = current_time
                datetime_dt = datetime.fromtimestamp(date_time)
            elif isinstance(date_time, str):
                datetime_dt = dateutil.parser.parse(date_time)
            elif isinstance(date_time, datetime):
                datetime_dt = date_time

        # if timestamp is none of the formats above, error message is printed and timestamp is set to current time by default
        except Exception as e:
            print(e)
            datetime_dt = datetime.now()

        # if timestamp is timezone naive, add timezone
        if not datetime_dt.tzinfo:
            # add system timezone and convert to UTC
            datetime_dt = get_localzone().localize(datetime_dt).astimezone(pytz.utc)

        # converts datetime to iso8601
        return datetime_dt.isoformat()

    def __get_token(self):
        """
        Retrieves the OAUTH token generated by your API key and API secret.
        this function has to be called before any API calls can be made
        """
        client_auth = requests.auth.HTTPBasicAuth(self.api_key, self.api_secret)
        post_data = {"grant_type": "client_credentials"}
        response = requests.post(self.auth, auth=client_auth, data=post_data)

        # raise exception if status code indicates an error
        if 400 <= response.status_code < 600:
            message = "{} {} Error: {}".format(response.status_code,
                                               "Client" if response.status_code < 500 else "Server",
                                               "unable to get token")
            raise HTTPError(message=message, response=response)
        return response.json()["access_token"]

    def __get_headers(self, is_json=False):
        """
        Create headers dictionary for a request.
        :param is_json: Whether the request body is a json.
        :return: The headers dictionary.
        """
        headers = {
            "Authorization": "Bearer " + self.__get_token(),
        }

        if self.client_type is not None:
            headers["Client-Type"] = self.client_type

        if self.client_version is not None:
            headers["Client-Version"] = self.client_version

        if self.client_metatag is not None:
            headers["Client-Metatag"] = self.client_metatag

        if is_json:
            headers['Content-Type'] = 'application/json'

        return headers

    def __request(self, method, path, headers=None, **kwargs):
        """
        A wrapper around requests.request that handles boilerplate code specific to TruStar's API.
        :param method: The method of the request ("GET", "PUT", "POST", or "DELETE")
        :param path: The path of the request, i.e. the piece of the URL after the base URL
        :param headers: A dictionary of headers that will be merged with the base headers for the SDK
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        :return: The response object.
        """

        # get headers and merge with headers from method parameter if it exists
        base_headers = self.__get_headers(is_json=method in ["POST", "PUT"])
        if headers is not None:
            base_headers.update(headers)

        # make request
        response = requests.request(method=method,
                                    url="{}/{}".format(self.base, path),
                                    headers=base_headers,
                                    verify=self.verify,
                                    **kwargs)

        # raise exception if status code indicates an error
        if 400 <= response.status_code < 600:
            if 'message' in response.json():
                reason = response.json()['message']
            else:
                reason = "unknown cause"
            message = "{} {} Error: {}".format(response.status_code,
                                               "Client" if response.status_code < 500 else "Server",
                                               reason)
            raise HTTPError(message, response=response)
        return response

    def __get(self, path, **kwargs):
        """
        Convenience method for making GET calls.
        :param path: The path of the request, i.e. the piece of the URL after the base URL
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__request("GET", path, **kwargs)

    def __put(self, path, **kwargs):
        """
        Convenience method for making PUT calls.
        :param path: The path of the request, i.e. the piece of the URL after the base URL
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__request("PUT", path, **kwargs)

    def __post(self, path, **kwargs):
        """
        Convenience method for making POST calls.
        :param path: The path of the request, i.e. the piece of the URL after the base URL
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__request("POST", path, **kwargs)

    def __delete(self, path, **kwargs):
        """
        Convenience method for making DELETE calls.
        :param path: The path of the request, i.e. the piece of the URL after the base URL
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__request("DELETE", path, **kwargs)

    def get_report_url(self, report_id):
        """
        Build direct URL to report from its ID
        :param report_id: Incident Report (IR) ID, e.g., as returned from `submit_report`
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        :return URL
        """

        # Check environment for URL
        base_url = 'https://station.trustar.co' if ('https://api.trustar.co' in self.base) else \
            self.base.split('/api/')[0]

        return "%s/constellation/reports/%s" % (base_url, report_id)


    #####################
    ### API Endpoints ###
    #####################

    def ping(self, **kwargs):
        """
        Ping the API.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__get("ping", **kwargs).content.decode('utf-8').strip('\n')

    def get_version(self, **kwargs):
        """
        Ping the API.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        return self.__get("version", **kwargs).content.decode('utf-8').strip('\n')


    ########################
    ### Report Endpoints ###
    ########################

    def get_report_details(self, report_id, id_type=None, **kwargs):
        """
        Retrieves the report details dictionary
        :param report_id: Incident Report ID
        :param id_type: indicates if ID is internal report guid or external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        :return Incident report dictionary if found, else exception.
        """
        params = {'idType': id_type}
        resp = self.__get("report/%s" % report_id, params=params, **kwargs)
        return json.loads(resp.content.decode('utf8'))

    def get_reports(self, distribution_type=DISTRIBUTION_TYPE_ENCLAVE, enclave_ids=None,
                    from_time=None, to_time=None, page_number=None, page_size=None, **kwargs):
        """
        Retrieves reports filtering by time window, distribution type, and enclave association.

        :param distribution_type: Optional, restrict reports to specific distribution type
        (by default all accessible reports are returned). Possible values are: 'COMMUNITY' and 'ENCLAVE'
        :param enclave_ids: Optional comma separated list of enclave ids, restrict reports to specific enclaves
        (by default reports from all enclaves are returned)
        :param from_time: Optional start of time window (Unix timestamp - seconds since epoch)
        :param to_time: Optional end of time window (Unix timestamp - seconds since epoch)
        :param page_number: The page number to get.
        :param page_size: The size of the page to be returned.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """

        # make enclave_ids default to configured list of enclave IDs
        if enclave_ids is None and distribution_type is not None and distribution_type.upper() == DISTRIBUTION_TYPE_ENCLAVE:
            enclave_ids = self.enclave_ids

        params = {
            'from': from_time,
            'to': to_time,
            'distributionType': distribution_type,
            'enclaveIds': enclave_ids,
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self.__get("reports", params=params, **kwargs)

        body = json.loads(resp.content.decode('utf8'))
        body['items'] = [Report.from_dict(report) for report in body['items']]

        return Page.from_dict(body)


    def submit_report(self, report_body=None, title=None, external_id=None, external_url=None, time_began=datetime.now(),
                      enclave=False, enclave_ids=None, report=None, **kwargs):
        """
        Wraps supplied text as a JSON-formatted TruSTAR Incident Report and submits it to TruSTAR Station
        By default, this submits to the TruSTAR community. To submit to your enclave(s), set enclave parameter to True,
        and ensure that the target enclaves' ids are specified in the config file field enclave_ids.
        :param report_body: body of report
        :param title: title of report
        :param external_id: external tracking id of report, optional if user doesn't have their own tracking id that they want associated with this report
        :param external_url: external url of report, optional and is associated with the original source of this report
        :param time_began: time report began
        :param enclave: boolean - whether or not to submit report to user's enclaves (see 'enclave_ids' config property)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """

        if report is None:
            if enclave_ids is None:
                enclave_ids = self.enclave_ids
            report = Report(title=title,
                            body=report_body,
                            time_began=time_began,
                            external_id=external_id,
                            external_url=external_url,
                            is_enclave=enclave,
                            enclave_ids=enclave_ids)

        payload = {
            'incidentReport': report.to_dict(),
            'enclaveIds': report.enclave_ids
        }

        resp = self.__post("report", data=json.dumps(payload), timeout=60, **kwargs)
        return resp.json()

    def update_report(self, report_id=None, id_type=None, title=None, report_body=None, time_began=None,
                      external_url=None, distribution=None, enclave_ids=None, report=None, **kwargs):
        """
        Updates report with the given id, overwrites any fields that are provided
        :param report_id: Incident Report ID
        :param id_type: indicates if ID is internal report guid or external ID provided by the user
        :param title: new title for report
        :param report_body: new body for report
        :param time_began: new time_began for report
        :param distribution: new distribution type for report
        :param enclave_ids: new list of enclave ids that the report will belong to (python list or comma-separated list)
        :param external_url: external url of report, optional and is associated with the original source of this report
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """

        if report is None:
            if enclave_ids is None:
                enclave_ids = self.enclave_ids
            report = Report(id=report_id,
                            title=title,
                            body=report_body,
                            time_began=time_began,
                            external_url=external_url,
                            is_enclave=distribution is None or distribution.upper() == Report.DISTRIBUTION_TYPE_ENCLAVE,
                            enclave_ids=enclave_ids)

        id_type = id_type or Report.ID_TYPE_INTERNAL

        if id_type.upper() == Report.ID_TYPE_EXTERNAL:
            report_id = report.external_id
        else:
            report_id = report.id


        params = {'idType': id_type}
        payload = {
            'incidentReport': report.to_dict(update=True),
            'enclaveIds': report.enclave_ids
        }

        resp = self.__put("report/%s" % report_id, data=json.dumps(payload), params=params, **kwargs)
        return json.loads(resp.content.decode('utf8'))

    def delete_report(self, report_id, id_type=None, **kwargs):
        """
        Deletes the report for the given id
        :param report_id: Incident Report ID
        :param id_type: indicates if ID is internal report guid or external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        params = {'idType': id_type}
        resp = self.__delete("report/%s" % report_id, params=params, **kwargs)
        return resp

    def get_correlated_reports(self, indicators, **kwargs):
        """
        Retrieves all TruSTAR reports that contain the searched indicator. You can specify multiple indicators
        separated by commas
        :param indicators: The list of indicators to retrieve correlated reports for.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        payload = {'indicators': indicators}
        resp = self.__get("reports/correlate", params=payload, **kwargs)
        return json.loads(resp.content.decode('utf8'))


    ###########################
    ### Indicator Endpoints ###
    ###########################

    # def query_latest_indicators(self, source, indicator_types, limit, interval_size, **kwargs):
    #     """
    #     Finds all latest indicators
    #     :param source: source of the indicators which can either be INCIDENT_REPORT or OSINT
    #     :param indicator_types: a list of indicators or a string equal to "ALL" to query all indicator types extracted
    #     by TruSTAR
    #     :param limit: limit on the number of indicators. Max is set to 5000
    #     :param interval_size: time interval on returned indicators. Max is set to 24 hours
    #     :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
    #     :return json response of the result
    #     """
    #     payload = {'source': source, 'types': indicator_types, 'limit': limit, 'intervalSize': interval_size}
    #     resp = self.__get("indicators/latest", params=payload, **kwargs)
    #     return json.loads(resp.content.decode('utf8'))

    def get_community_trends(self, indicator_type=None, from_time=None, to_time=None, page_size=None, page_number=None, **kwargs):
        """
        Find community trending indicators.
        :param indicator_type: the type of indicators.  3 types are supported: "malware", "cve" (vulnerabilities),
        "other" (all
        other types of indicators)
        :param from_time: Optional start of time window (Unix timestamp - seconds since epoch)
        :param to_time: Optional end of time window (Unix timestamp - seconds since epoch)
        :param page_size: # of results on returned page
        :param start_page: page to start returning results on
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        :return: json response of the result
        """

        payload = {
            'type': indicator_type,
            'from': from_time,
            'to': to_time,
            'pageSize': page_size,
            'pageNumber': page_number
        }
        resp = self.__get("indicators/community-trending", params=payload, **kwargs)
        return Page.from_dict(json.loads(resp.content.decode('utf8')))

    def get_related_indicators(self, indicators=None, sources=None, page_number=None, page_size=None, **kwargs):
        """
         Finds all reports that contain the indicators and returns correlated indicators from those reports.
         :param indicators: list of indicators to search for
         :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
         """
        params = {
            'indicators': indicators,
            'sources': sources,
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self.__get("indicators/related", params=params, **kwargs)
        return Page.from_dict(json.loads(resp.content.decode('utf8')))

    def get_related_external_indicators(self, indicators=None, sources=None, **kwargs):
        """
         Finds all reports that contain the indicators and returns correlated indicators from those reports.
         :param indicators: list of indicators to search for
         :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
         """
        params = {
            'indicators': indicators,
            'sources': sources
        }
        resp = self.__get("indicators/external/related", params=params, **kwargs)
        return json.loads(resp.content.decode('utf8'))


    #####################
    ### Tag Endpoints ###
    #####################

    def get_enclave_tags(self, report_id, id_type=None, **kwargs):
        """
        Retrieves the enclave tags present in a specific report
        :param report_id: Incident Report ID
        :param id_type: Optional, indicates if ID is internal report guid or external ID provided by the user
        (default Internal)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        params = {'idType': id_type}
        resp = self.__get("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return json.loads(resp.content.decode('utf8'))

    def add_enclave_tag(self, report_id, name, enclave_id, id_type=None, **kwargs):
        """
        Adds a tag to a specific report, in a specific enclave
        :param report_id: Incident Report ID
        :param name: name of the tag to be added
        :param enclave_id: id of the enclave where the tag will be added
        :param id_type: Optional, indicates if ID is internal report guid or external ID provided by the user
        (default Internal)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        params = {
            'idType': id_type,
            'name': name,
            'enclaveId': enclave_id
        }
        resp = self.__post("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return json.loads(resp.content.decode('utf8'))

    def delete_enclave_tag(self, report_id, name, enclave_id, id_type=None, **kwargs):
        """
        Deletes a tag from a specific report, in a specific enclave
        :param report_id: Incident Report ID
        :param name: name of the tag to be deleted
        :param enclave_id: id of the enclave where the tag will be deleted
        :param id_type: Optional, indicates if ID is internal report guid or external ID provided by the user
        (default Internal)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to requests.request.
        """
        params = {
            'idType': id_type,
            'name': name,
            'enclaveId': enclave_id
        }
        resp = self.__delete("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return resp.content.decode('utf8')


    #################
    ### Iterators ###
    #################

    @staticmethod
    def get_page_iterator(func, start_page=0, page_size=None):
        page_number = start_page
        more_pages = True
        while more_pages:
            page = func(page_number=page_number, page_size=page_size)
            yield page
            more_pages = page.has_more_pages()
            page_number += 1

    @classmethod
    def get_iterator(cls, func=None, page_iterator=None):

        if page_iterator is None:
            if func is None:
                raise Exception("To use 'get_iterator', must provide either a page iterator or a method.")
            else:
                page_iterator = cls.get_page_iterator(func)

        for page in page_iterator:
            for item in page.items:
                yield item

    def get_report_page_iterator(self, start_page=0, page_size=None, **kwargs):
        def func(page_number, page_size):
            return self.get_reports(page_number=page_number, page_size=page_size, **kwargs)

        return self.get_page_iterator(func, start_page, page_size)

    def get_report_iterator(self, **kwargs):
        return self.get_iterator(page_iterator=self.get_report_page_iterator(**kwargs))

    def get_community_trends_page_iterator(self, start_page=0, page_size=None, **kwargs):
        def func(page_number, page_size):
            return self.get_community_trends(page_number=page_number, page_size=page_size, **kwargs)

        return self.get_page_iterator(func, start_page, page_size)

    def get_community_trends_iterator(self, **kwargs):
        return self.get_iterator(page_iterator=self.get_community_trends_page_iterator(**kwargs))

    def get_related_indicators_page_iterator(self, start_page=0, page_size=None, **kwargs):
        def func(page_number, page_size):
            return self.get_related_indicators(page_number=page_number, page_size=page_size, **kwargs)

        return self.get_page_iterator(func, start_page, page_size)

    def get_related_indicators_iterator(self, **kwargs):
        return self.get_iterator(page_iterator=self.get_related_indicators_page_iterator(**kwargs))


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
            'timeBegan': TruStar.normalize_timestamp(self.time_began),
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


class Page(object):

    def __init__(self, items=None, page_number=None, page_size=None, total_elements=None):
        self.items = items
        self.page_number = page_number
        self.page_size = page_size
        self.total_elements = total_elements

    def get_total_pages(self):
        return math.ceil(self.total_elements / self.page_size)

    def has_more_pages(self):
        return self.page_number < self.get_total_pages()

    @staticmethod
    def from_dict(page):
        return Page(items=page['items'],
                    page_number=page['pageNumber'],
                    page_size=page['pageSize'],
                    total_elements=page['totalElements'])

    def to_dict(self):
        items = []
        for item in self.items:
            if hasattr(item, 'to_dict'):
                items.append(item.to_dict())
            else:
                items.append(item)

        return {
            'items': items,
            'pageNumber': self.page_number,
            'pageSize': self.page_size,
            'totalElements': self.total_elements
        }

    def __str__(self):
        return json.dumps(self.to_dict())
