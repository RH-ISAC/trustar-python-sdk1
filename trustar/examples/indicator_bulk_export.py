"""
This script will initiate a bulk export of all indicator metadata for indicators
that contain google.com and save them to a local file.  In order to work
correctly, the api_endpoint in your config must be for 2.0 (<host>/api/2.0)
"""

from time import sleep

from trustar import datetime_to_millis, log, TruStar

# initialize SDK
ts = TruStar()

# initialize logger
logger = log.get_logger(__name__)

guid = ts.initiate_indicator_metadata_export('google.com')
logger.info("Job initiated - %s" % guid)

sleep(10)
status = ts.get_indicator_metadata_export_status(guid)
logger.info("Status = %s" % status)

# Loop until the status is either ERROR or COMPLETE
while status != "ERROR" and status != "COMPLETE":
    sleep(10)
    status = ts.get_indicator_metadata_export_status(guid)
    logger.info("Status = %s" % status)

if status == "ERROR":
    logger.error("Job failed")
else:
    logger.info("Saving export to %s.csv" % guid)
    ts.download_indicator_metadata_export(guid, "%s.csv" % guid)
    logger.info("Export complete!")

