#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function
from trustar import TruStar
import json
from random import randint
import dateutil.parser

do_latest_reports = True
do_correlated = True
do_latest_indicators = True
do_query_indicators = True
do_comm_submissions = True
do_enclave_submissions = True

do_submit_report = True
do_report_details_by_ext_id = True
do_update_report_by_ext_id = True
do_report_details_by_guid = True
do_update_report_by_guid = True
do_release_report_by_ext_id = True
do_report_details_by_ext_id_2 = True
do_delete_report_by_ext_id = True

# search_string = "1.2.3.4 8.8.8.8 10.0.2.1 185.19.85.172 art-archiv.ru"
search_string = "167.114.35.70,103.255.61.39,miel-maroc.com,malware.exe"
submit_indicators = "google.com malware.exe 103.255.61.39"

verify = True


def main():
    ts = TruStar(config_role="trustar")

    # generate random id to use as external_id
    external_id = str(randint(1, 100000))

    # or use a specific external_id
    # external_id = "321"
    report_guid = None

    if do_latest_reports:
        token = ts.get_token(verify=verify)
        print("Getting Latest Accessible Reports...")

        results = ts.get_latest_reports(token, verify=verify)
        for result in results:
            print("\t%s, %s, %s" % (result['id'], result['distributionType'], result['title']))
        print()

    if do_correlated:
        token = ts.get_token(verify=verify)
        print("Querying Accessible Correlated Reports...")
        results = ts.get_correlated_reports(token, search_string, verify=verify)
        print("%d report(s) correlated with indicators '%s':\n" % (len(results), search_string))
        print("\n".join(results))
        print()

    if do_latest_indicators:
        token = ts.get_token(verify=verify)
        print("Get Latest Indicators (first 100)")

        results = ts.query_latest_indicators(token, source='INCIDENT_REPORT', indicator_types='ALL', interval_size=24,
                                             limit=100, verify=verify)
        if 'indicators' in results:
            for ioc_type, value in results['indicators'].items():
                if len(value) > 0:
                    print("\t%s:  %s" % (ioc_type, ','.join(value)))
            print()

    if do_query_indicators:
        token = ts.get_token(verify=verify)
        print("Querying correlated indicators with search string '%s' (first 100)" % search_string)
        results = ts.query_indicators(token, search_string, '100', verify=verify)

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
        token = ts.get_token(verify=verify)
        community_response = ts.submit_report(token, submit_indicators, "COMMUNITY API SUBMISSION TEST",
                                              time_began="2017-02-01T01:23:45", verify=verify)
        print("\tURL: %s\n" % ts.get_report_url(community_response['reportId']))

        if 'reportIndicators' in community_response:
            print("Extracted the following community indicators: \n%s\n" % json.dumps(
                community_response['reportIndicators'], indent=2))

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        token = ts.get_token(verify=verify)
        enclave_response = ts.submit_report(token, submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True, verify=verify)
        print("\tURL: %s\n" % ts.get_report_url(enclave_response['reportId']))

        print(enclave_response)

        if 'reportIndicators' in enclave_response:
            print("Extracted the following enclave indicators: \n%s\n" %
                  json.dumps(enclave_response['reportIndicators'], indent=2))

    # Submit a test report and retrieve it
    if do_submit_report:
        token = ts.get_token(verify=verify)
        print("Submit Report")
        submission_response = ts.submit_report(token, submit_indicators, "Sample SDK Test Report",
                                               external_id=external_id,
                                               time_began="2017-02-01T01:23:45", enclave=True, verify=verify)

        print("Report Submitted")
        print("\texternalTrackingId: %s" % submission_response['externalTrackingId'])
        print("\tindicators: %s" % submission_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(submission_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_ext_id:
        token = ts.get_token(verify=verify)
        print("Get Report")
        result = ts.get_report_details(token, report_id=external_id, id_type="external", verify=verify)

        print("Report Details using External ID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))
        report_guid = result['id']

    # Update a test report and test with get report
    if do_update_report_by_ext_id:
        token = ts.get_token(verify=verify)
        print("Update Report")
        title = "Updated Sample Title"
        body = "updated report body: 21.22.23.24"
        update_response = ts.update_report(token, report_id=external_id, id_type="external", title=title,
                                           report_body=body,
                                           verify=verify)

        print("Updated Report using External ID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_guid:
        token = ts.get_token(verify=verify)
        print("Get Report")
        result = ts.get_report_details(token, report_guid, id_type="internal", verify=verify)

        print("Report Details using GUID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Update a test report and test with get report
    if do_update_report_by_guid:
        token = ts.get_token(verify=verify)
        print("Update Report")
        title = "New Sample Title"
        body = "new sample body - 7.8.9.10"
        update_response = ts.update_report(token, report_guid, id_type="internal", title=title, report_body=body,
                                           verify=verify)

        print("Updated Report using GUID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_guid:
        token = ts.get_token(verify=verify)
        print("Get Report")
        result = ts.get_report_details(token, report_guid, id_type="internal", verify=verify)

        print("Report Details using GUID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Release report to community
    if do_release_report_by_ext_id:
        token = ts.get_token(verify=verify)
        print("Release Report")
        update_response = ts.update_report(token, report_id=external_id, id_type='external', distribution="COMMUNITY",
                                           verify=verify)

        print("Report Released using External ID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_ext_id_2:
        token = ts.get_token(verify=verify)
        print("Get Report")
        result = ts.get_report_details(token, report_id=external_id, id_type="external", verify=verify)

        print("Report Details using External ID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Delete test report previously submitted
    if do_delete_report_by_ext_id:
        token = ts.get_token(verify=verify)
        print("Delete Report")
        response = ts.delete_report(token, report_id=external_id, id_type="external", verify=verify)
        print("Report Deleted using External ID")


if __name__ == '__main__':
    main()
