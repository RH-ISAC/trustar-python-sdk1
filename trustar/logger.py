import logging
from logging.config import dictConfig
from .utils import parse_boolean
import os
import sys


DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "detailed": {
            "class": "logging.Formatter",
            "format": "%(asctime)s - %(levelname)-7s - %(name)s:%(lineno)d - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "detailed"
        },
    },
    "root": {
        "level": "INFO",
        "handlers": [
            "console"
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
