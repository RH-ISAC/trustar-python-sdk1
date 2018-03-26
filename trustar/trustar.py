# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str
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
import time
from requests import HTTPError
import functools

# package imports
from .models import Indicator, Page, Tag, Report, DistributionType, IdType, EnclavePermissions
from .utils import normalize_timestamp, get_logger, get_time_based_page_generator
from .version import __version__, __api_version__

# python 2 backwards compatibility
standard_library.install_aliases()

logger = get_logger(__name__)


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
        'base': 'https://api.trustar.co/api/1.3',
        'client_type': 'PYTHON_SDK',
        'client_version': __version__,
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
        | ``api_endpoint``        | No        | ``"https://api.trustar.co/api/1.3"``             | the base URL used for making API calls                 |
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
            config = self.config_from_file(config_file, config_role)

        # remap config keys names
        for k, v in self.REMAPPED_KEYS.items():
            if k in config and v not in config:
                config[v] = config[k]

        # override Nones with default values if they exist
        for key, val in TruStar.DEFAULTS.items():
            if config.get(key) is None:
                config[key] = val

        # ensure required properties are present
        for key in TruStar.REQUIRED_KEYS:
            if config.get(key) is None:
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

        # get API version and strip "beta" tag
        # This comes from base url passed in config
        # e.g. https://api.trustar.co/api/1.3-beta will give 1.3
        api_version = self.base.strip("/").split("/")[-1]

        # strip beta tag
        BETA_TAG = "-beta"
        api_version = api_version.strip(BETA_TAG)

        # /api resolves to version 1.2
        if api_version.lower() == "api":
            api_version = "1.2"

        # if API version does not match expected version, log a warning
        if api_version.strip(BETA_TAG) != __api_version__.strip(BETA_TAG):
            logger.warn("This version (%s) of the TruStar Python SDK is only compatible with version %s of"
                        " the TruStar Rest API, but is attempting to contact version %s of the Rest API."
                        % (__version__, __api_version__, api_version))

        # initialize token property
        self.token = None

    @staticmethod
    def config_from_file(config_file_path, config_role):
        """
        Create a configuration dictionary from a config file section.  This dictionary is what the TruStar
        class constructor ultimately requires.

        :param config_file_path: The path to the config file.
        :param config_role: The section within the file to use.
        :return: The configuration dictionary.
        """

        # read config file depending on filetype, parse into dictionary
        ext = os.path.splitext(config_file_path)[-1]
        if ext in ['.conf', '.ini']:
            config_parser = configparser.RawConfigParser()
            config_parser.read(config_file_path)
            roles = dict(config_parser)
        elif ext in ['.json', '.yml', '.yaml']:
            with open(config_file_path, 'r') as f:
                roles = yaml.load(f)
        else:
            raise IOError("Unrecognized filetype for config file '%s'" % config_file_path)

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

        return config

    @staticmethod
    def normalize_timestamp(date_time):
        return normalize_timestamp(date_time)

    def _get_token(self):
        """
        Returns the token.  If no token has been generated yet, gets one first.
        :return: The OAuth2 token.
        """

        if self.token is None:
            self._refresh_token()
        return self.token

    def _refresh_token(self):
        """
        Retrieves the OAuth2 token generated by the user's API key and API secret.
        Sets the instance property 'token' to this new token.
        If the current token is still live, the server will simply return that.
        """

        # use basic auth with API key and secret
        client_auth = requests.auth.HTTPBasicAuth(self.api_key, self.api_secret)

        # make request
        post_data = {"grant_type": "client_credentials"}
        response = requests.post(self.auth, auth=client_auth, data=post_data)

        # raise exception if status code indicates an error
        if 400 <= response.status_code < 600:
            message = "{} {} Error: {}".format(response.status_code,
                                               "Client" if response.status_code < 500 else "Server",
                                               "unable to get token")
            raise HTTPError(message, response=response)

        # set token property to the received token
        self.token = response.json()["access_token"]

    def _get_headers(self, is_json=False):
        """
        Create headers dictionary for a request.

        :param boolean is_json: Whether the request body is a json.
        :return: The headers dictionary.
        """

        headers = {"Authorization": "Bearer " + self._get_token()}

        if self.client_type is not None:
            headers["Client-Type"] = self.client_type

        if self.client_version is not None:
            headers["Client-Version"] = self.client_version

        if self.client_metatag is not None:
            headers["Client-Metatag"] = self.client_metatag

        if is_json:
            headers['Content-Type'] = 'application/json'

        return headers

    @classmethod
    def _is_expired_token_response(cls, response):
        """
        Determine whether the given response indicates that the token is expired.

        :param response: The response object.
        :return: True if the response indicates that the token is expired.
        """

        EXPIRED_MESSAGE = "Expired oauth2 access token"
        INVALID_MESSAGE = "Invalid oauth2 access token"

        if response.status_code == 400:
            try:
                body = response.json()
                if str(body.get('error_description')) in [EXPIRED_MESSAGE, INVALID_MESSAGE]:
                    return True
            except:
                pass
        return False

    def _request(self, method, path, headers=None, params=None, data=None, **kwargs):
        """
        A wrapper around ``requests.request`` that handles boilerplate code specific to TruStar's API.

        :param str method: The method of the request (``GET``, ``PUT``, ``POST``, or ``DELETE``)
        :param str path: The path of the request, i.e. the piece of the URL after the base URL
        :param dict headers: A dictionary of headers that will be merged with the base headers for the SDK
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        retry = True
        while retry:

            # get headers and merge with headers from method parameter if it exists
            base_headers = self._get_headers(is_json=method in ["POST", "PUT"])
            if headers is not None:
                base_headers.update(headers)

            # make request
            response = requests.request(method=method,
                                        url="{}/{}".format(self.base, path),
                                        headers=base_headers,
                                        verify=self.verify,
                                        params=params,
                                        data=data,
                                        **kwargs)

            # refresh token if expired
            if self._is_expired_token_response(response):
                self._refresh_token()

            # if "too many requests" status code received, wait until next request will be allowed and retry
            elif response.status_code == 429:
                wait_time = response.json().get('waitTime')
                logger.debug("Waiting %d seconds until next request allowed." % wait_time)
                time.sleep(wait_time)

            # request cycle is complete
            else:
                retry = False

        # raise exception if status code indicates an error
        if 400 <= response.status_code < 600:

            # get response json body, if one exists
            resp_json = None
            try:
                resp_json = response.json()
            except:
                pass

            # get message from json body, if one exists
            if resp_json is not None and 'message' in resp_json:
                reason = resp_json['message']
            else:
                reason = "unknown cause"

            # construct error message
            message = "{} {} Error: {}".format(response.status_code,
                                               "Client" if response.status_code < 500 else "Server",
                                               reason)
            # raise HTTPError
            raise HTTPError(message, response=response)

        return response

    def _get(self, path, params=None, **kwargs):
        """
        Convenience method for making ``GET`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self._request("GET", path, params=params, **kwargs)

    def _put(self, path, params=None, data=None, **kwargs):
        """
        Convenience method for making ``PUT`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self._request("PUT", path, params=params, data=data, **kwargs)

    def _post(self, path, params=None, data=None, **kwargs):
        """
        Convenience method for making ``POST`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self._request("POST", path, params=params, data=data, **kwargs)

    def _delete(self, path, params=None, **kwargs):
        """
        Convenience method for making ``DELETE`` calls.

        :param str path: The path of the request, i.e. the piece of the URL after the base URL.
        :param kwargs: Any extra keyword arguments.  These will be forwarded to the call to ``requests.request``.
        :return: The response object.
        """

        return self._request("DELETE", path, params=params, **kwargs)

    def get_report_url(self, report_id):
        """
        Build a direct URL to a report's graph in the Station User Interface from the report's ID.

        :param str report_id: the guid of the report
        :return: the URL

        Example:

        >>> get_report_url("ce2a3010-249a-11e8-b467-0ed5f89f718b")
        https://station.trustar.co/constellation/reports/ce2a3010-249a-11e8-b467-0ed5f89f718b
        """

        # Check environment for URL
        base_url = 'https://station.trustar.co' if ('https://api.trustar.co' in self.base) else \
            self.base.split('/api/')[0]

        return "%s/constellation/reports/%s" % (base_url, report_id)


    #####################
    ### API Endpoints ###
    #####################

    def ping(self):
        """
        Ping the API.

        Example:

        >>> ts.ping()
        pong
        """

        result = self._get("ping").content

        if isinstance(result, bytes):
            result = result.decode('utf-8')

        return result.strip('\n')

    def get_version(self):
        """
        Get the version number of the API.

        Example:

        >>> ts.get_version()
        1.3
        """

        result = self._get("version").content

        if isinstance(result, bytes):
            result = result.decode('utf-8')

        return result.strip('\n')


    ########################
    ### Report Endpoints ###
    ########################

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
        resp = self._get("reports/%s" % report_id, params=params)
        return Report.from_dict(resp.json())

    def get_reports_page(self, is_enclave=None, enclave_ids=None, tag=None, excluded_tags=None,
                         from_time=None, to_time=None):
        """
        Retrieves a page of reports, filtering by time window, distribution type, enclave association, and tag.
        The results are sorted by updated time.
        This method does not take ``page_number`` and ``page_size`` parameters.  Instead, each successive page must be
        found by adjusting the ``from_time`` and ``to_time`` parameters.

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
        if is_enclave == True:
            distribution_type = DistributionType.ENCLAVE
        elif is_enclave == False:
            distribution_type = DistributionType.COMMUNITY

        if enclave_ids is None:
            enclave_ids = self.enclave_ids

        params = {
            'from': from_time,
            'to': to_time,
            'distributionType': distribution_type,
            'enclaveIds': enclave_ids,
            'tag': tag,
            'excludedTags': excluded_tags
        }
        resp = self._get("reports", params=params)
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
        resp = self._post("reports", data=data, timeout=60)

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
        self._put("reports/%s" % report_id, data=data, params=params)

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
        self._delete("reports/%s" % report_id, params=params)

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
        resp = self._get("reports/correlate", params=params)
        return resp.json()

    def get_correlated_reports_page(self, indicators, enclave_ids=None, is_enclave=True,
                                    page_size=None, page_number=None):
        """
        Retrieves a page of all TruSTAR reports that contain the searched indicators.

        :param indicators: A list of indicator values to retrieve correlated reports for.
        :param enclave_ids: The enclaves to search in.
        :param is_enclave: Whether to search enclave reports or community reports.
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
            'distributionType': distribution_type
        }
        resp = self._get("reports/correlated", params=params)

        return Page.from_dict(resp.json(), content_type=Report)

    def search_reports_page(self, search_term, enclave_ids=None, page_size=None, page_number=None):
        """
        Search for reports containing a search term.

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :param int page_number: the page number to get.
        :param int page_size: the size of the page to be returned.
        :return: a |Page| of |Report| objects.
        """

        params = {
            'searchTerm': search_term,
            'enclaveIds': enclave_ids,
            'pageSize': page_size,
            'pageNumber': page_number
        }

        resp = self._get("reports/search", params=params)
        page = Page.from_dict(resp.json(), content_type=Report)

        return page


    ###########################
    ### Indicator Endpoints ###
    ###########################

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
        resp = self._get("reports/%s/indicators" % report_id, params=params)
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

        resp = self._get("indicators/community-trending", params=params)
        body = resp.json()

        # parse items in response as indicators
        return map(Indicator.from_dict, body)

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

        resp = self._get("indicators/related", params=params)

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

        resp = self._get("indicators/search", params=params)

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
        resp = self._get("indicators/details", params=params)

        return map(Indicator.from_dict, resp.json())


    #####################
    ### Tag Endpoints ###
    #####################

    def get_enclave_tags(self, report_id, id_type=None):
        """
        Retrieves all enclave tags present in a specific report.

        :param report_id: the ID of the report
        :param id_type: indicates whether the ID internal or an external ID provided by the user
        :return: A list of  |Tag| objects.
        """

        params = {'idType': id_type}
        resp = self._get("reports/%s/tags" % report_id, params=params)
        return map(Tag.from_dict, resp.json())

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
        resp = self._post("reports/%s/tags" % report_id, params=params)
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
        self._delete("reports/%s/tags/%s" % (report_id, tag_id), params=params)

    def get_all_enclave_tags(self, enclave_ids=None):
        """
        Retrieves all tags present in the given enclaves. If the enclave list is empty, the tags returned include all
        tags for all enclaves the user has access to.

        :param enclave_ids: list of enclave IDs
        :return: The list of |Tag| objects.
        """

        params = {'enclaveIds': enclave_ids}
        resp = self._get("reports/tags", params=params)
        return map(Tag.from_dict, resp.json())

    #########################
    ### Enclave Endpoints ###
    #########################

    def get_user_enclaves(self):
        """
        Gets the list of enclaves that the user has access to.

        :return: A list of |EnclavePermissions| objects, each representing an enclave and whether the requesting user
            has read, create, and update access to it.
        """

        resp = self._get("enclaves")
        return map(EnclavePermissions.from_dict, resp.json())


    ###########################
    ### Whitelist Endpoints ###
    ###########################

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
        resp = self._get("whitelist", params=params)
        return Page.from_dict(resp.json(), content_type=Indicator)

    def add_terms_to_whitelist(self, terms):
        """
        Add a list of terms to the user's company's whitelist.

        :param terms: The list of terms to whitelist.
        :return: The list of extracted |Indicator| objects that were whitelisted.
        """

        resp = self._post("whitelist", json=terms)
        return map(Indicator.from_dict, resp.json())

    def delete_indicator_from_whitelist(self, indicator):
        """
        Delete an indicator from the user's company's whitelist.

        :param indicator: An |Indicator| object, representing the indicator to delete.
        """

        params = indicator.to_dict()
        self._delete("whitelist", params=params)


    ##################
    ### Generators ###
    ##################

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
        Uses the |get_reports_page| method to create a generator that returns each successive report.

        :param boolean is_enclave: restrict reports to specific distribution type (optional - by default all accessible
            reports are returned).
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific
            enclaves (optional - by default reports from all enclaves are returned)
        :param str tag: name of tag to filter reports by.  if a tag with this name exists in more than one enclave
            indicated in ``enclave_ids``, the request will fail.  handle this by making separate requests for each
            enclave ID if necessary.
        :param int from_time: start of time window in milliseconds since epoch (optional)
        :param int to_time: end of time window in milliseconds since epoch (optional)
        :return: The generator.

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

        :param str search_term: The term to search for.
        :param list(str) enclave_ids: list of enclave ids used to restrict reports to specific enclaves (optional - by
            default reports from all of user's enclaves are returned)
        :return: The generator.
        """

        return Page.get_generator(page_generator=self._search_reports_page_generator(search_term, enclave_ids))

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
