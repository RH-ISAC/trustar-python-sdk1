#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function

import json

from trustar import TruStar

do_latest_reports = True
do_correlated = True
do_report_details = True
do_query_indicators = True
do_latest_indicators = True
do_comm_submissions = True
do_enclave_submissions = True

# search_string = "1.2.3.4 8.8.8.8 10.0.2.1 185.19.85.172 art-archiv.ru"
search_string = "167.114.35.70,103.255.61.39,miel-maroc.com,malware.exe"
submit_indicators = "google.com malware.exe 103.255.61.39"


def main():
    ts = TruStar(config_role="trustar")
    token = ts.get_token()
    if do_latest_reports:
        print("Getting Latest Accessible Reports...")

        results = ts.get_latest_reports(token)
        for result in results:
            print("\t%s, %s, %s" % (result['id'], result['distributionType'], result['title']))
        print()

    if do_correlated:
        print("Querying Accessible Correlated Reports...")
        results = ts.get_correlated_reports(token, search_string)
        print("%d report(s) correlated with indicators '%s':\n" % (len(results), search_string))
        print("\n".join(results))
        print()

    if do_latest_indicators:
        print("Get Latest Indicators (first 100)")

        results = ts.query_latest_indicators(token, source='INCIDENT_REPORT', indicator_types='ALL', interval_size=24,
                                             limit=100)
        if 'indicators' in results:
            for ioc_type, value in results['indicators'].iteritems():
                if len(value) > 0:
                    print("\t%s:  %s" % (ioc_type, ','.join(value)))
            print()

    if do_report_details:
        print("Get Report Details")

        reports = ts.get_latest_reports(token)

        for report in reports:
            result = ts.get_report_details(token, report['id'])
            print("Getting Report Details using '%s': \n%s" % (report['id'], json.dumps(result, indent=4)))
            print()

    if do_query_indicators:
        print("Querying correlated indicators with search string '%s' (first 100)" % search_string)
        results = ts.query_indicators(token, search_string, '100')

        indicator_hits = list(results["indicators"])
        if len(indicator_hits) > 0:
            print("Correlated Incident Report Indicators:")
            for indicator_type, indicator_list in list(results["indicators"].items()):
                print("\n%s:\n\t%s" % (indicator_type, "\n\t".join(['{}'.format(value) for value in indicator_list])))
            print()

        os_hits = list(results["openSourceCorrelations"])
        if len(os_hits) > 0:
            print("Correlated Open Source Documents:")
            for os_url in os_hits:
                print("\t%s" % os_url)
            print()

        exint_hits = list(results["externalIntelligence"])
        if len(exint_hits) > 0:
            print("External Intelligence hits:")
            print('\t'.join(exint_hits))
            print()

    # Submit simple test report to community
    if do_comm_submissions:
        community_response = ts.submit_report(token, submit_indicators, "COMMUNITY API SUBMISSION TEST",
                                              began_time="2017-02-01T01:23:45")
        print("\tURL: %s\n" % ts.get_report_url(community_response['reportId']))

        if 'reportIndicators' in community_response:
            print("Extracted the following community indicators: \n%s\n" % json.dumps(
                community_response['reportIndicators'], indent=2))

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        enclave_response = ts.submit_report(token, submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True)
        print("\tURL: %s\n" % ts.get_report_url(enclave_response['reportId']))

        if 'reportIndicators' in enclave_response:
            print("Extracted the following enclave indicators: \n%s\n" %
                  json.dumps(enclave_response['reportIndicators'], indent=2))


if __name__ == '__main__':
    main()
