from trustar import TruStar, get_logger
from datetime import datetime, timedelta
import time


"""
This script will delete all reports for your enclaves that were submitted yesterday.
This is just an example, DO NOT RUN THIS UNLESS YOU ARE SURE YOU REALLY WANT TO!!!
"""

ts = TruStar()

logger = get_logger(__name__)

# set 'from' to the start of yesterday and 'to' to the end of yesterday
from_time = datetime.now() - timedelta(days=2)
to_time = datetime.now() - timedelta(days=1)

# convert times to milliseconds since epoch
from_time = int(time.mktime(from_time.timetuple())) * 1000
to_time = int(time.mktime(to_time.timetuple())) * 1000

count = 0
reports = None
while reports is None or len(reports) > 0:
    try:
        reports = ts.get_reports_page(from_time=from_time,
                                      to_time=to_time,
                                      is_enclave=True,
                                      enclave_ids=ts.enclave_ids)

        logger.info("Total remaining reports: %s" % reports.total_elements)
        for report in reports:
            logger.info("deleting report %s" % report.id)
            ts.delete_report(report_id=report.id)
            count += 1
    except Exception as e:
        logger.error("Error: %s" % e)

logger.info("\nDeleted %d reports." % count)
