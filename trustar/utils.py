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


DAY = 24 * 60 * 60 * 1000


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


def get_current_time_millis():
    """
    :return: the current time in milliseconds since epoch.
    """
    return int(time.time()) * 1000


def datetime_to_millis(dt):
    """
    Convert a ``datetime`` object to milliseconds since epoch.
    """
    return int(time.mktime(dt.timetuple())) * 1000


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
    stderr_handler.setLevel(logging.INFO)

    # configure logger
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    log.addHandler(stdout_handler)
    log.addHandler(stderr_handler)

    return log


def get_time_based_page_generator(get_page, get_next_to_time, from_time=None, to_time=None):

    if to_time is None:
        to_time = get_current_time_millis()

    if from_time is None:
        from_time = to_time - DAY

    while to_time is not None and from_time <= to_time:
        result = get_page(from_time, to_time)
        yield result
        new_to_time = get_next_to_time(result)
        if new_to_time is not None:
            if new_to_time > to_time:
                raise Exception("to_time should not increase between page iterations.  "
                                "This can result in an endless loop.")
            new_to_time -= 1
        to_time = new_to_time


logger = get_logger(__name__)
