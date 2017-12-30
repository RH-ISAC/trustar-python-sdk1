# python 2 backwards compatibility
from __future__ import print_function
from builtins import object
from future import standard_library
from six import string_types

# external imports
import json
from datetime import datetime
import configparser
import os
import requests
import requests.auth
import yaml
from requests import HTTPError

# package imports
from .models import Indicator, Page, Tag, Report
from .utils import normalize_timestamp, get_logger

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


CLIENT_VERSION = "0.3.2"


class TruStar(object):
    """
    This class is used to interact with the TruStar API.
    """

    # raise exception if any of these config keys are missing
    REQUIRED_KEYS = ['api_key', 'api_secret']

    # allow configs to use different key names for config values
    REMAPPED_KEYS = {
        'auth_endpoint': 'auth',
        'api_endpoint': 'base',
        'user_api_key': 'api_key',
        'user_api_secret': 'api_secret'
    }

    # default config values
    DEFAULTS = {
        'auth': 'https://api.trustar.co/oauth/token',
        'base': 'https://api.trustar.co/api/1.3-beta',
        'client_type': 'PYTHON_SDK',
        'client_version': CLIENT_VERSION,
        'client_metatag': None,
        'verify': True
    }

    def __init__(self, config_file="trustar.conf", config_role="trustar", config=None):
        """
        Constructs and configures the instance.  Initially attempts to use ``config``; if it is ``None``,
        then attempts to use ``config_file`` instead.

        The only required config keys are ``user_api_key`` and ``user_api_secret``.  To obtain these values, login to
        TruSTAR Station in your browser and visit the **API** tab under **SETTINGS** to generate an API key and secret.

        The other available keys, and their defaults, are listed below:

        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | key                     | required  | default                                          | description                                            |
        +=========================+===========+==================================================+========================================================+
        | ``user_api_key``        | Yes       | ``True``                                         | API key                                                |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``user_api_secret``     | Yes       | ``True``                                         | API secret                                             |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``enclave_ids``         | No        | ``[]``                                           | a list (or comma-separated list) of enclave ids        |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``auth_endpoint``       | No        | ``"https://api.trustar.co/oauth/token"``         | the URL used to obtain OAuth2 tokens                   |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``api_endpoint``        | No        | ``"https://api.trustar.co/api/1.3-beta"``        | the base URL used for making API calls                 |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``verify``              | No        | ``True``                                         | whether to use SSL verification                        |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``client_type``         | No        | ``"Python_SDK"``                                 | the name of the client being used                      |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``client_version``      | No        | the version of the Python SDK in use             | the version of the client being used                   |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+
        | ``client_metatag``      | No        | ``None``                                         | any additional information (ex. email address of user) |
        +-------------------------+-----------+--------------------------------------------------+--------------------------------------------------------+

        :param str config_file: Path to configuration file (conf, json, or yaml).
        :param str config_role: The section in the configuration file to use.
        :param dict config: A dictionary of configuration options.
        """

        # attempt to use configuration file if one exists
        if config is None:

            if config is not None:
                raise Exception("Cannot use 'config' parameter if also using 'config_file' parameter.")

            # read config file depending on filetype, parse into dictionary
            ext = os.path.splitext(config_file)[-1]
            if ext in ['.conf', '.ini']:
                config_parser = configparser.RawConfigParser()
                config_parser.read(config_file)
                roles = dict(config_parser)
            elif ext in ['.json', '.yml', '.yaml']:
                with open(config_file, 'r') as f:
                    roles = yaml.load(f)
            else:
                raise IOError("Unrecognized filetype for config file '%s'" % config_file)

            # ensure that config file has indicated role
            if config_role in roles:
                config = dict(roles[config_role])
            else:
                raise KeyError("Could not find role %s" % config_role)

            # parse enclave ids
            if 'enclave_ids' in config:
                # if id has all numeric characters, will be parsed as an int, so convert to string
                if isinstance(config['enclave_ids'], int):
                    config['enclave_ids'] = str(config['enclave_ids'])
                # split comma separated list if necessary
                if isinstance(config['enclave_ids'], string_types):
                    config['enclave_ids'] = config['enclave_ids'].split(',')
                elif not isinstance(config['enclave_ids'], list):
                    raise Exception("'enclave_ids' must be a list or a comma-separated list")
                # strip out whitespace
                config['enclave_ids'] = [str(x).strip() for x in config['enclave_ids'] if x is not None]
            else:
                # default to empty list
                config['enclave_ids'] = []

        # remap config keys names
        for k, v in self.REMAPPED_KEYS.items():
            if k in config and v not in config:
                config[v] = config[k]

        # set properties from config dict
        for key, val in config.items():
            if val is None:
                # override None with default value
                if key in TruStar.DEFAULTS:
                    config[key] = TruStar.DEFAULTS[key]
                # ensure required properties are present
                if val in TruStar.REQUIRED_KEYS:
                    raise Exception("Missing config value for %s" % key)

        # set properties
        self.auth = config.get('auth')
        self.base = config.get('base')
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        self.client_type = config.get('client_type')
        self.client_version = config.get('client_version')
        self.client_metatag = config.get('client_metatag')
        self.verify = config.get('verify')
        self.enclave_ids = config.get('enclave_ids')

        if isinstance(self.enclave_ids, str):
            self.enclave_ids = [self.enclave_ids]

    @staticmethod
    def normalize_timestamp(date_time):
        return normalize_timestamp(date_time)

    def __get_token(self):
        """
        Retrieves the OAUTH token generated by your API key and API secret.
        This function should be called before any API call is made.
        """

        client_auth = requests.auth.HTTPBasicAuth(self.api_key, self.api_secret)
        post_data = {"grant_type": "client_credentials"}
        response = requests.post(self.auth, auth=client_auth, data=post_data)

        # raise exception if status code indicates an error
        if 400 <= response.status_code < 600:
            message = "{} {} Error: {}".format(response.status_code,
                                               "Client" if response.status_code < 500 else "Server",
                                               "unable to get token")
            raise HTTPError(message, response=response)
        return response.json()["access_token"]

    def __get_headers(self, is_json=False):
        """
        Create headers dictionary for a request.

        :param boolean is_json: Whether the request body is a json.
        :return: The headers dictionary.
        """

        headers = {"Authorization": "Bearer " + self.__get_token()}

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
        A wrapper around ``requests.request`` that handles boilerplate code specific to TruStar's API.

        :param str method: The method of the request (``GET``, ``PUT``, ``POST``, or ``DELETE``)
        :param str path: The path of the request, i.e. the piece of the URL after the base URL
        :param dict headers: A dictionary of headers that will be merged with the base headers for the SDK
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
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
        Convenience method for making ``GET`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self.__request("GET", path, **kwargs)

    def __put(self, path, **kwargs):
        """
        Convenience method for making ``PUT`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self.__request("PUT", path, **kwargs)

    def __post(self, path, **kwargs):
        """
        Convenience method for making ``POST`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self.__request("POST", path, **kwargs)

    def __delete(self, path, **kwargs):
        """
        Convenience method for making ``DELETE`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self.__request("DELETE", path, **kwargs)

    def get_report_url(self, report_id):
        """
        Build a direct URL to a report's graph in the Station User Interface from the report's ID.

        :param str report_id: the guid of the report
        :return: the URL
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

        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        Example:

        >>> ts.ping()
        pong
        """

        return self.__get("ping", **kwargs).content.decode('utf-8').strip('\n')

    def get_version(self, **kwargs):
        """
        Get the version number of the API.

        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        Example:

        >>> ts.get_version()
        1.3-beta
        """

        return self.__get("version", **kwargs).content.decode('utf-8').strip('\n')


    ########################
    ### Report Endpoints ###
    ########################

    def get_report_details(self, report_id, id_type=None, **kwargs):
        """
        Retrieves a report by its ID.  Internal and external IDs are both allowed.

        :param str report_id: The ID of the incident report.
        :param str id_type: Indicates whether ID is internal or external.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        :return: The retrieved |Report| object.

        Example:

        >>> report = ts.get_report_details(report_id)
        >>> print(report)
        {
          "reportBody": "Employee reported suspect email.  We had multiple reports of suspicious email overnight ...",
          "title": "Phishing Incident",
          "enclaves": ["ac6a0d17-7350-4410-bc57-9699521db992"],
          "distributionType": "ENCLAVE",
          "timeBegan": 1479941278000,
          "indicators": [
            {
              "type": "IP",
              "value": "89.108.83.45"
            },
            {
              "type": "IP",
              "value": "185.143.241.126"
            },
            ...
          ]
        }

        """

        params = {'idType': id_type}
        resp = self.__get("reports/%s" % report_id, params=params, **kwargs)
        return Report.from_dict(resp.json())

    def get_reports_page(self, is_enclave=None, enclave_ids=None, tag=None,
                         from_time=None, to_time=None, page_number=None, page_size=None, **kwargs):
        """
        Retrieves a page of reports, filtering by time window, distribution type, enclave association, and tag.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param str tag: name of tag to filter reports by.
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        :return: A |Page| of |Report| objects.

        Example:

        >>> page = ts.get_reports_page(is_enclave=True, tag="malicious",
        >>>                            from_time=1495695711000, to_time=1514185311000,
        >>>                            page_number=1, page_size=5)
        >>> print([report.id for report in page])
        ['661583cb-a6a7-4cbd-8a90-01578fa4da89', 'da131660-2708-4c8a-926e-f91fb5dbbc62', '2e3400d6-fa37-4a8c-bc2f-155aaa02ae5a', '38064828-d3db-4fff-8ab8-e0e3b304ff44', 'dbf26104-cee5-4ca4-bdbf-a01d0178c007']
        >>> print(len(page))
        5

        """

        distribution_type = None

        # explicitly compare to True and False to distinguish from None (which is treated as False in a conditional)
        if is_enclave == True:
            distribution_type = Report.DISTRIBUTION_TYPE_ENCLAVE
        elif is_enclave == False:
            distribution_type = Report.DISTRIBUTION_TYPE_COMMUNITY

        if enclave_ids is None:
            enclave_ids = self.enclave_ids

        params = {
            'from': from_time,
            'to': to_time,
            'distributionType': distribution_type,
            'enclaveIds': enclave_ids,
            'tag': tag,
            'pageNumber': page_number,
            'pageSize': page_size
        }
        resp = self.__get("reports", params=params, **kwargs)
        page = Page.from_dict(resp.json())

        # replace each dict in 'items' with a Report object
        page.items = [Report.from_dict(report) for report in page.items]

        # create a Page object from the dict
        return page

    def submit_report(self, report, **kwargs):
        """
        Submits a report.

        * If ``report.is_enclave`` is ``True``, then the report will be submitted to the enclaves
          identified by ``report.enclaves``; if that field is ``None``, then the enclave IDs registered with this
          |TruStar| object will be used.
        * If ``report.time_began`` is ``None``, then the current time will be used.

        :param report: The |Report| object that was submitted, with the ``id`` and ``indicators`` fields updated based
            on values from the response.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        Example:

        >>> report = Report(title="Suspicious Activity",
        >>>                 body="We have been receiving suspicious requests from 169.178.68.63.",
        >>>                 enclave_ids=["602d4795-31cd-44f9-a85d-f33cb869145a"])
        >>> report = ts.submit_report(report)
        >>> print(report.id)
        ac6a0d17-7350-4410-bc57-9699521db992
        >>> print(report.title)
        Suspicious Activity
        >>> print(report.indicators[0].value)
        169.178.68.63
        """

        # make distribution type default to "enclave"
        if report.is_enclave is None:
            report.is_enclave = True

        if report.enclaves is None:
            # use configured enclave_ids by default if distribution type is ENCLAVE
            if report.is_enclave:
                report.set_enclave_ids(self.enclave_ids)
            # if distribution type is COMMUNITY, API still expects non-null list of enclaves
            else:
                report.enclaves = []

        if report.time_began is None:
            report.time_began = datetime.now()

        payload = {
            'incidentReport': report.to_dict(),
            'enclaveIds': report.get_enclave_ids()
        }
        resp = self.__post("reports", data=json.dumps(payload), timeout=60, **kwargs)
        body = resp.json()

        # get report id from response body
        report.id = body['reportId']

        # parse indicators from response body
        report.indicators = []
        for indicator_type, indicators in body.get('reportIndicators').items() or []:
            for value in indicators:
                report.indicators.append(Indicator(value=value, type=indicator_type))

        return report

    def update_report(self, report, **kwargs):
        """
        Updates the report identified by the ``report.id`` field; if this field does not exist, then
        ``report.external_id`` will be used if it exists.  Any other fields on ``report`` that are not ``None``
        will overwrite values on the report on Station.

        :param report: A |Report| object with the updated values.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The |Report| object with any updated values returned in the response.

        Example:

        >>> report = ts.get_report_details(report_id)
        >>> print(report.title)
        Old Title
        >>> report.title = "Changed title"
        >>> updated_report = ts.update_report(report)
        >>> print(updated_report.title)
        Changed Title
        """

        if report.id is not None:
            id_type = Report.ID_TYPE_INTERNAL
            report_id = report.id
        elif report.external_id is not None:
            id_type = Report.ID_TYPE_EXTERNAL
            report_id = report.external_id
        else:
            raise Exception("Cannot update report without either an ID or an external ID.")

        # not allowed to update value of 'externalTrackingId', so remove it
        report_dict = {k: v for k, v in report.to_dict().items() if k != 'reportId'}

        params = {'idType': id_type}
        payload = {
            'incidentReport': report_dict,
            'enclaveIds': report.get_enclave_ids()
        }

        resp = self.__put("reports/%s" % report_id, data=json.dumps(payload), params=params, **kwargs)
        body = resp.json()

        # set IDs from response body
        report.id = body.get('reportId')
        report.external_id = body.get('externalTrackingId')

        # parse indicators from response body
        report.indicators = []
        for indicator_type, indicators in body.get('reportIndicators').items() or []:
            for value in indicators:
                report.indicators.append(Indicator(value=value, type=indicator_type))

        return report

    def delete_report(self, report_id, id_type=None, **kwargs):
        """
        Deletes the report with the given id.

        :param report_id: the ID of the report to delete
        :param id_type: indicates whether the ID is internal or an external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: the response object

        Example:

        >>> response = ts.delete_report(report_id)
        >>> print(response.content)
        OK
        """

        params = {'idType': id_type}
        resp = self.__delete("reports/%s" % report_id, params=params, **kwargs)
        return resp

    def get_correlated_report_ids(self, indicators, **kwargs):
        """
        Retrieves a list of the IDs of all TruSTAR reports that contain the searched indicator.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The list of IDs of reports that correlated.

        Example:

        >>> report_ids = ts.get_correlated_report_ids(["wannacry", "www.evil.com"])
        >>> print(report_ids)
        ["e3bc6921-e2c8-42eb-829e-eea8da2d3f36", "4d04804f-ff82-4a0b-8586-c42aef2f6f73"]
        """

        params = {'indicators': indicators}
        resp = self.__get("reports/correlate", params=params, **kwargs)
        return resp.json()


    ###########################
    ### Indicator Endpoints ###
    ###########################

    def get_community_trends_page(self, indicator_type=None, from_time=None, to_time=None,
                                  page_size=None, page_number=None, **kwargs):
        """
        Find community trending indicators.

        :param indicator_type: A type of indicator to filter by.  If ``None``, will get all types of indicators except
            for MALWARE and CVEs (this convention is for parity with the corresponding view on the Dashboard).
        :param from_time: start of time window in milliseconds since epoch
        :param to_time: end of time window in milliseconds since epoch
        :param page_size: number of results per page
        :param page_number: page to start returning results on
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: A |Page| of |Indicator| objects.
        """

        params = {
            'type': indicator_type,
            'from': from_time,
            'to': to_time,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        resp = self.__get("indicators/community-trending", params=params, **kwargs)
        page = Page.from_dict(resp.json())

        # parse items in response as indicators
        page.items = [Indicator.from_dict(item) for item in page.items]

        return page

    def get_related_indicators_page(self, indicators=None, sources=None, page_size=None, page_number=None, **kwargs):
        """
        Finds all reports that contain any of the given indicators and returns correlated indicators from those reports.

        :param indicators: list of indicator values to search for
        :param sources: list of sources to search.  Options are: INCIDENT_REPORT, EXTERNAL_INTELLIGENCE, and ORION_FEED.
        :param page_size: number of results per page
        :param page_number: page to start returning results on
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: A |Page| of |Report| objects.
        """

        params = {
            'indicators': indicators,
            'types': sources,
            'pageNumber': page_number,
            'pageSize': page_size
        }

        resp = self.__get("indicators/related", params=params, **kwargs)
        page = Page.from_dict(resp.json())

        # parse items in response as indicators
        page.items = [Indicator.from_dict(item) for item in page.items]

        return page

    def get_related_external_indicators(self, indicators=None, sources=None, **kwargs):
        """
        Searches external systems for indicators that correlate with the given list of indicators.

        :param indicators: list of indicator values to search for
        :param sources: list of sources to search (check your Managed Integrations for a list of possible values)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: A dictionary where each key is one of the sources queries and each value is a dictionary containing
            the information returned from that external source.
        """

        params = {
            'indicators': indicators,
            'sources': sources
        }
        resp = self.__get("indicators/external/related", params=params, **kwargs)
        return resp.json()


    #####################
    ### Tag Endpoints ###
    #####################

    def get_enclave_tags(self, report_id, id_type=None, **kwargs):
        """
        Retrieves all enclave tags present in a specific report.

        :param report_id: the ID of the report
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: A list of  |Tag| objects.
        """

        params = {'idType': id_type}
        resp = self.__get("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return [Tag.from_dict(tag) for tag in resp.json()]

    def add_enclave_tag(self, report_id, name, enclave_id, id_type=None, **kwargs):
        """
        Adds a tag to a specific report, for a specific enclave.

        :param report_id: The ID of the report
        :param name: The name of the tag to be added
        :param enclave_id: id of the enclave where the tag will be added
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: A |Tag| object representing the tag that was created.
        """

        params = {
            'idType': id_type,
            'name': name,
            'enclaveId': enclave_id
        }
        resp = self.__post("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return Tag.from_dict(resp.json())

    def delete_enclave_tag(self, report_id, name, enclave_id, id_type=None, **kwargs):
        """
        Deletes a tag from a specific report, in a specific enclave.

        :param report_id: The ID of the report
        :param name: The name of the tag to be deleted
        :param enclave_id: id of the enclave where the tag will be added
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response body.
        """

        params = {
            'idType': id_type,
            'name': name,
            'enclaveId': enclave_id
        }
        resp = self.__delete("reports/%s/enclave-tags" % report_id, params=params, **kwargs)
        return resp.content.decode('utf8')

    def get_all_enclave_tags(self, enclave_ids=None, **kwargs):
        """
        Retrieves all tags present in the given enclaves. If the enclave list is empty, the tags returned include all
        tags for all enclaves the user has access to.

        :param enclave_ids: list of enclave IDs
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The list of |Tag| objects.
        """

        params = {'enclaveIds': enclave_ids}
        resp = self.__get("enclave-tags", params=params, **kwargs)
        return [Tag.from_dict(tag) for tag in resp.json()]


    ##################
    ### Generators ###
    ##################

    def __get_reports_page_generator(self, is_enclave=None, enclave_ids=None, tag=None, from_time=None, to_time=None,
                                     start_page=0, page_size=None, **kwargs):
        """
        Creates a generator from the |get_reports_page| method that returns each successive page.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param str tag: name of tag to filter reports by.\
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        :return: The generator.
        """

        def func(page_number, page_size):
            return self.get_reports_page(is_enclave, enclave_ids, tag, from_time, to_time,
                                         page_number, page_size, **kwargs)

        return Page.get_page_generator(func, start_page, page_size)

    def get_reports(self, is_enclave=None, enclave_ids=None, tag=None, from_time=None, to_time=None, **kwargs):
        """
        Uses the |get_reports_page| method to create a generator that returns each successive report.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param str tag: name of tag to filter reports by.
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.

        :return: The generator.
        """

        return Page.get_generator(page_generator=self.__get_reports_page_generator(is_enclave, enclave_ids, tag,
                                                                                   from_time, to_time, **kwargs))

    def __get_community_trends_page_generator(self, indicator_type=None, from_time=None, to_time=None,
                                              start_page=0, page_size=None, **kwargs):
        """
        Creates a generator from the |get_community_trends_page| method that returns each successive page.

        :param indicator_type: A type of indicator to filter by.  If ``None``, will get all types of indicators except
            for MALWARE and CVEs (this convention is for parity with the corresponding view on the Dashboard).
        :param from_time: start of time window in milliseconds since epoch
        :param to_time: end of time window in milliseconds since epoch
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to the
            |get_community_trends_page| method.
        :return: The generator.
        """

        def func(page_number, page_size):
            return self.get_community_trends_page(indicator_type, from_time, to_time,
                                                  page_number=page_number, page_size=page_size, **kwargs)

        return Page.get_page_generator(func, start_page, page_size)

    def get_community_trends(self, indicator_type=None, from_time=None, to_time=None, **kwargs):
        """
        Uses the |get_community_trends_page| method to create a generator that returns each successive report.

        :param indicator_type: A type of indicator to filter by.  If ``None``, will get all types of indicators except
            for MALWARE and CVEs (this convention is for parity with the corresponding view on the Dashboard).
        :param from_time: start of time window in milliseconds since epoch
        :param to_time: end of time window in milliseconds since epoch
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to the
            |get_community_trends_page| method.
        :return: The generator.
        """

        return Page.get_generator(page_generator=self.__get_community_trends_page_generator(indicator_type, from_time,
                                                                                            to_time, **kwargs))

    def __get_related_indicators_page_generator(self, indicators=None, sources=None, start_page=0, page_size=None, **kwargs):
        """
        Creates a generator from the |get_related_indicators_page| method that returns each
        successive page.

        :param indicators: list of indicator values to search for
        :param sources: list of sources to search.  Options are: INCIDENT_REPORT, EXTERNAL_INTELLIGENCE, and ORION_FEED.
        :param start_page: The page to start on.
        :param page_size: The size of each page.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to the
            |get_related_indicators_page| method.
        :return: The generator.
        """

        def func(page_number, page_size):
            return self.get_related_indicators_page(indicators, sources, page_number=page_number,
                                                    page_size=page_size, **kwargs)

        return Page.get_page_generator(func, start_page, page_size)

    def get_related_indicators(self, indicators=None, sources=None, **kwargs):
        """
        Uses the |get_related_indicators_page| method to create a generator that returns each successive report.

        :param indicators: list of indicator values to search for
        :param sources: list of sources to search.  Options are: INCIDENT_REPORT, EXTERNAL_INTELLIGENCE, and ORION_FEED.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to the
            |get_related_indicators_page| method.
        :return: The generator.
        """

        return Page.get_generator(page_generator=self.__get_related_indicators_page_generator(indicators, sources,
                                                                                              **kwargs))
