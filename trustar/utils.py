# python 2 backwards compatibility
from __future__ import print_function
from six import string_types

# external imports
import sys
import logging
import time
from datetime import datetime
import dateutil.parser
import pytz
from tzlocal import get_localzone

# package imports
from .models import Enclave


def normalize_timestamp(date_time):
    """
    Attempt to convert a string timestamp in to a TruSTAR compatible format for submission.
    Will return current time with UTC time zone if None
    :param date_time: int that is seconds or milliseconds since epoch, or string/datetime object containing date, time,
    and (ideally) timezone.
    Examples of supported timestamp formats: 1487890914, 1487890914000, "2017-02-23T23:01:54", "2017-02-23T23:01:54+0000"
    :return If input is an int, will return milliseconds since epoch.  Otherwise, will return a normalized isoformat
    timestamp.
    """
    datetime_dt = datetime.now()

    # get current time in seconds-since-epoch
    current_time = int(time.time()) * 1000

    try:
        # identify type of timestamp and convert to datetime object
        if isinstance(date_time, int):

            # if timestamp has less than 10 digits, it is in seconds
            if date_time < 10000000000:
                date_time *= 1000

            # if timestamp is incorrectly forward dated, set to current time
            if date_time > current_time:
                raise ValueError("The given time %s is in the future." % date_time)

            return date_time

        if isinstance(date_time, str):
            datetime_dt = dateutil.parser.parse(date_time)
        elif isinstance(date_time, datetime):
            datetime_dt = date_time

    # if timestamp is none of the formats above, error message is printed and timestamp is set to current time by
    # default
    except Exception as e:
        logger.warn(e)
        logger.warn("Using current time as replacement.")
        datetime_dt = datetime.now()

    # if timestamp is timezone naive, add timezone
    if not datetime_dt.tzinfo:
        # add system timezone and convert to UTC
        datetime_dt = get_localzone().localize(datetime_dt).astimezone(pytz.utc)

    # converts datetime to iso8601
    return datetime_dt.isoformat()


def enclaves_from_ids(enclave_ids):
    """
    Create enclave objects from a list of ids.
    :param enclave_ids: A list, or comma-separated list, of enclave guids.
    :return: A list of Enclave objects.
    """

    # if string, convert comma-separated list into python list
    if isinstance(enclave_ids, string_types):
        enclave_ids = [x.strip() for x in enclave_ids.split(',')]

    # ensure is list
    if not isinstance(enclave_ids, list):
        raise ValueError("Enclave IDs must either be a list or a comma-separated string.")

    # create Enclave objects and filter out None values
    return [Enclave(id=id) for id in enclave_ids if id is not None]


def get_logger(name=None):
    """
    Configures a logger to log to STDOUT or STDERR based on the logging level of the message.
    :param name: The name of the logger.
    :return: The logger.
    """

    class InfoFilter(logging.Filter):
        def filter(self, rec):
            return rec.levelno <= logging.INFO

    # configure STDOUT handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    stdout_handler.setLevel(logging.INFO)
    stdout_handler.addFilter(InfoFilter())

    # configure STDERR handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    stderr_handler.setLevel(logging.WARN)

    # configure logger
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    log.addHandler(stdout_handler)
    log.addHandler(stderr_handler)

    return log


logger = get_logger(__name__)
