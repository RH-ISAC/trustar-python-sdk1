#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function

import json

from trustar import TruStar

do_latest = True
do_correlated = True
do_query_indicator = True
do_comm_submissions = True
do_enclave_submissions = True

query_indicators = "1.2.3.4,8.8.8.8,10.0.2.1,185.19.85.172"
submit_indicators = "google.com,malware.exe"


def main():
    ts = TruStar(config_role="trustar")
    token = ts.get_token()
    if do_latest:
        print("Get Latest Reports")

        results = ts.get_latest_reports(token)

        for result in results:
            print("\t{}, {}, {}".format(result['id'], result['distributionType'], result['title']))
        print()

    if do_correlated:
        print("Query Correlated Reports")
        results = ts.get_correlated_reports(token, query_indicators)
        print("{} report(s) correlated with indicators '{}': ".format(len(results), query_indicators))
        for result in results:
            print("\t%s" % result)
        print()

    if do_query_indicator:
        print("Query Correlated Indicators (first 100)")
        results = ts.query_indicator(token, query_indicators, "100")
        print("{} indicators type(s) correlated with indicators '{}': ".format(len(results["indicators"]),
                                                                               query_indicators))

        for indicator_type, indicator_list in list(results["indicators"].items()):
            print("\t%s: %s" % (indicator_type, ",".join(['{}'.format(value) for value in indicator_list])))
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


if __name__ == '__main__':
    main()
