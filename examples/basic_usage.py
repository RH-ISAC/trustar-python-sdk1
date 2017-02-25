#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function

import json

from datetime import datetime
import dateutil.parser
import dateutil.tz
import pytz

from trustar import TruStar

do_latest_reports = True
do_correlated = True
do_query_indicators = True
do_latest_indicators = True
do_comm_submissions = True
do_enclave_submissions = True
do_submit_reports = True

# search_string = "1.2.3.4 8.8.8.8 10.0.2.1 185.19.85.172 art-archiv.ru"
search_string = "167.114.35.70,103.255.61.39,miel-maroc.com"
submit_indicators = "google.com malware.exe"


def main():
    ts = TruStar(config_role="trustar")
    token = ts.get_token()
    if do_latest_reports:
        print("Get Latest Reports")

        results = ts.get_latest_reports(token)


        for result in results:
            print("\t{}, {}, {}".format(result['id'], result['distributionType'], result['title']))
        print()

    if do_correlated:
        print("Querying Correlated Reports")
        results = ts.get_correlated_reports(token, search_string)
        print(results)
        print("{} report(s) correlated with indicators '{}': ".format(len(results), search_string))
        for result in results:
            print("\t%s" % result)
        print()

    if do_latest_indicators:
        print("Get Latest Indicators (first 100)")

        results = ts.query_latest_indicators(token, source='INCIDENT_REPORT', indicator_types='ALL', interval_size=24,
                                             limit=100)
        if 'indicators' in results:
            for ioc_type, value in results['indicators'].iteritems():
                if len(value) > 0:
                    print("\t{}:  {}".format(ioc_type, ','.join(value)))
            print()

    if do_query_indicators:
        print("Querying correlated indicators with '{}' (first 100)".format(search_string))
        results = ts.query_indicators(token, search_string, '100')

        print("Correlated Incident Report indicators:")
        for indicator_type, indicator_list in list(results["indicators"].items()):
            print("\n%s:\n\t%s" % (indicator_type, "\n\t".join(['{}'.format(value) for value in indicator_list])))
        print()

        print("Correlated Open Source documents:")
        for os_url in list(results["openSourceCorrelations"]):
            print("\t%s" % os_url)
        print()

        print("External Intelligence hits:")
        for exint_url in list(results["externalIntelligence"]):
            print("\t%s" % exint_url)
        print()

    # Submit simple test report to community
    if do_comm_submissions:
        community_response = ts.submit_report(token, submit_indicators, "COMMUNITY API SUBMISSION TEST ")
        print("Community submission response: {0}".format(json.dumps(community_response)))
        if 'reportIndicators' in community_response:
            print("Extracted the following community indicators: {}".format(community_response['reportIndicators']))

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        enclave_response = ts.submit_report(token, submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True)
        print("Enclave submission response: {0}".format(json.dumps(enclave_response)))

        if 'reportIndicators' in enclave_response:
            print("Extracted the following enclave indicators: {}".format(enclave_response['reportIndicators']))

    # Submit simple latest 5 community reports with diff format beganTime timestamps
    if do_submit_reports:
        print("Testing Different Report Format Submissions")

        ts_src = TruStar(config_role="production")
        token_src = ts_src.get_token()
        results = ts_src.get_latest_reports(token_src)

        for result in results:
            if len(result['indicators']) <= 150:
                break;

        i = 1

        # sample timestamp used for testing: 1487890914000
        timestamps = {1487890914000, "2017-02-23T23:01:54", "2017-02-23T23:01:54+0000", dateutil.parser.parse("2017-02-23T23:01:54"), dateutil.parser.parse("2017-02-23T23:01:54+0000")}
        for timestamp in timestamps:
            print("~~~Submission " + str(i) + "~~~")
            print("Timestamp (original): " + str(timestamp))
            if isinstance(timestamp, int):
                print("Timestamp type: int")
            elif isinstance(timestamp, str):
                print("Timestamp type: string")
            elif isinstance(timestamp, datetime):
                print("Timestamp type: datetime")
            else:
                print("Timestamp type: unknown")
            test_tstamp_submission(ts, token, ts_src, result, timestamp)
            i = i+1


def test_tstamp_submission(ts, token, ts_src, result, tstamp):
    community_response = ts.submit_report(token, result['reportBody'], result['title'], tstamp)
    print("~~Original Report~~")
    print("SRC Report ID: %s" % (result['id']))
    print("Distribution Type: %s" % (result['distributionType']))
    print("->Time Began (converted): %s" % (ts_src.normalize_timestamp(result['timeBegan'])))
    print("~~New Report~~")
    print("DEST Report ID: %s" % (community_response['reportId']))
    print()


if __name__ == '__main__':
    main()
