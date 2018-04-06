from __future__ import print_function
from builtins import object, str
from future import standard_library
from six import string_types

# external imports
import configparser
import os
import requests
import requests.auth
import yaml
import time
from requests import HTTPError

# package imports
from .utils import get_logger
from .version import __version__, __api_version__

logger = get_logger(__name__)


class ApiClient(object):
    """
    This class is used to make HTTP requests to the TruStar API.
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
        for key, val in self.DEFAULTS.items():
            if config.get(key) is None:
                config[key] = val

        # ensure required properties are present
        for key in self.REQUIRED_KEYS:
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
