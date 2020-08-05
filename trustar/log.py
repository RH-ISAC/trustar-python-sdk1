# Seems like from time to time people do a from trustar import *, lets minimize the chances of something ugly happening
__all__ = ["get_logger"]

import datetime
import logging
import os
import sys

import json_log_formatter

from .config import LOGGING_ENV_VAR


class TrustarJSONFormatter(json_log_formatter.JSONFormatter):
    """
    Custom class to override the default behaviour of the JSONFormatter
    """
    def json_record(self, message, extra, record):
        extra['message'] = message
        extra['level'] = record.levelname
        extra['module'] = record.name
        extra['time'] = datetime.datetime.utcnow()
        if record.exc_info:
            extra['exec_info'] = self.formatException(record.exc_info)
        return extra


def get_handler():
    """
    Gets the handler to manage the output of the logger, default: stdout
    """
    handler = logging.StreamHandler(sys.stdout)
    # TODO: read from a config file, or env var, and override the default formatter.
    # IE: logging.FileHandler(filename='/path/to/file.log')
    return handler


def get_formatter():
    formatter = TrustarJSONFormatter
    # TODO: read from a config file, or env var, and override the default formatter.
    return formatter()


def get_logging_level():
    return int(os.environ.get(LOGGING_ENV_VAR, logging.INFO))


output_handler = get_handler()
output_handler.setFormatter(get_formatter())


def get_logger(name=None):
    logger = logging.getLogger(name or __name__)
    logger.addHandler(output_handler)
    logger.setLevel(get_logging_level())
    return logger
