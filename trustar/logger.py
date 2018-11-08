# python 2 backwards compatibility
from __future__ import print_function
from builtins import object, str, super
from future import standard_library
from six import string_types

import logging
from logging.config import dictConfig
from .utils import parse_boolean
import os
import sys


class InfoFilter(logging.Filter):
    """
    Filters log messages based on whether their level is less than or equal to INFO.
    """

    def __init__(self, below):
        super().__init__()
        self.below = below

    def filter(self, rec):
        less_than = rec.levelno <= logging.INFO
        return less_than if self.below else not less_than


DEFAULT_LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'infoFilter': {
            '()': InfoFilter,
            'below': True
        },
        'errorFilter': {
            '()': InfoFilter,
            'below': False
        }
    },
    'formatters': {
        'detailed': {
            'class': 'logging.Formatter',
            'format': '%(asctime)s - %(levelname)-7s - %(name)s:%(lineno)d - %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filters': ['infoFilter'],
            'stream': 'ext://sys.stdout',
        },
        'error_console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'detailed',
            'filters': ['errorFilter'],
            'stream': 'ext://sys.stderr',
        },
    },
    'root': {
        'level': 'INFO',
        'handlers': [
            'console',
            'error_console'
        ]
    }
}


def configure_logging():
    """
    Initialize logging configuration to defaults.  If the environment variable DISABLE_TRUSTAR_LOGGING is set to true,
    this will be ignored.
    """

    if not parse_boolean(os.environ.get('DISABLE_TRUSTAR_LOGGING')):

        # configure
        dictConfig(DEFAULT_LOGGING_CONFIG)

        # construct error logger
        error_logger = logging.getLogger("error")

        # log all uncaught exceptions
        def log_exception(exc_type, exc_value, exc_traceback):
            error_logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

        # register logging function as exception hook
        sys.excepthook = log_exception
