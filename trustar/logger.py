import logging
from logging.config import dictConfig
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
    if not os.environ.get('DISABLE_TRUSTAR_LOGGING'):
        dictConfig(DEFAULT_LOGGING_CONFIG)

        error_logger = logging.getLogger("error")

        def log_exception(exc_type, exc_value, exc_traceback):
            error_logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

        sys.excepthook = log_exception
