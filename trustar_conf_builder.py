"""
This is a helper script that will produce a 'trustar.conf' file.
It will load the following mandatory envvars into the file:
    * AUTH_ENDPOINT
    * API_ENDPOINT
    * STATION_BASE_URL
    * API_KEY
    * API_SECRET
    * CLIENT_METATAG
"""
import configparser
import os
import logging
from trustar.indicator_client import logger

logger = logging.getLogger("Conf Builder")
environment_variables = [
    "AUTH_ENDPOINT",
    "API_ENDPOINT",
    "STATION_BASE_URL",
    "API_KEY",
    "API_SECRET",
    "CLIENT_METATAG",
]
try:
    logger.info("Checking env vars")
    for k in environment_variables:
        if not os.getenv(k):
            raise KeyError(f"{k} env var is missing")
    
    logger.info("Creating config parser")
    config = configparser.ConfigParser()
    config["trustar"] = config["staging"] = {"auth_endpoint": os.getenv("AUTH_ENDPOINT"),
                                             "api_endpoint": os.getenv("API_ENDPOINT"),
                                             "user_api_key": os.getenv("API_KEY"),
                                             "user_api_secret": os.getenv("API_SECRET"),
                                             "client_metatag": os.getenv("CLIENT_METATAG"),
                                             "enclave_ids": os.getenv("ENCLAVE_IDS")}
    with open("trustar.conf", "w") as conf_file:
        logger.info("Writing conf file")
        config.write(conf_file)
except Exception as ex:
    logger.error(ex)
else:
    logger.info("trustar.conf generated")
