#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function

import json
import sys
import time
from random import randint

from trustar import TruStar

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
    role = "trustar"
    if len(sys.argv) > 1:
        role = sys.argv[1]

    ts = TruStar(config_role=role)

    # generate random id to use as external_id
    external_id = str(randint(1, 100000))

    # or use a specific external_id
    # external_id = "321"

    report_guid = None

    if do_latest_reports:

        current_time = int(time.time())

        print("Getting Latest Accessible Incident Reports Since 24 hours ago ...")
        try:
            token = ts.get_token(verify=verify)
            results = ts.get_reports(token, from_time=current_time - 1 * 24 * 60 * 60, to_time=current_time,
                                     verify=verify)

            # print(results.get('status'))
            # print(results.get('pageSize'))
            # print(results.get('totalPages'))
            # print(results.get('pageNumber'))
            # print(results.get('moreResults'))
            # print(results.get('totalElements'))
            print("Got %s results" % (results.get('totalElements')))

            # print(json.dumps(results))

            for result in results.get('data').get('reports'):
                print(result)
            print()

        except Exception as e:
            print('Could not get latest reports, error: %s' % e)

    if do_correlated:
        print("Querying Accessible Correlated Reports...")
        try:
            token = ts.get_token(verify=verify)
            results = ts.get_correlated_reports(token, search_string, verify=verify)

            print(results)
            print("%d report(s) correlated with indicators '%s':\n" % (len(results), search_string))
            print("\n".join(results))
            print()
        except Exception as e:
            print('Could not get correlated reports, error: %s' % e)

    if do_latest_indicators:
        print("Get Latest Indicators (first 100)")

        try:
            token = ts.get_token(verify=verify)

            results = ts.query_latest_indicators(token, source='INCIDENT_REPORT', indicator_types='ALL',
                                                 interval_size=24,
                                                 limit=100, verify=verify)
            if 'indicators' in results:
                for ioc_type, value in results['indicators'].items():
                    if len(value) > 0:
                        print("\t%s:  %s" % (ioc_type, ','.join(value)))
                print()
        except Exception as e:
            print('Could not get latest indicators, error: %s' % e)

    if do_query_indicators:
        print("Querying Correlated Indicators with Search String '%s' (first 100)" % search_string)
        try:
            token = ts.get_token(verify=verify)
            results = ts.query_indicators(token, search_string, '100', verify=verify)

            indicator_hits = list(results["indicators"])
            if len(indicator_hits) > 0:
                print("Correlated Incident Report Indicators:")
                for indicator_type, indicator_list in list(results["indicators"].items()):
                    print(
                        "\n%s:\n\t%s" % (indicator_type, "\n\t".join(['{}'.format(value) for value in indicator_list])))
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

        except Exception as e:
            print('Could not get correlated indicators, error: %s' % e)

    # Submit simple test report to community
    if do_comm_submissions:
        print("Submit New Community Incident Report")
        try:
            token = ts.get_token(verify=verify)
            response = ts.submit_report(token, submit_indicators, "COMMUNITY API SUBMISSION TEST",
                                        time_began="2017-02-01T01:23:45", verify=verify)
            print("\tURL: %s\n" % ts.get_report_url(response['reportId']))

            if 'reportIndicators' in response:
                print("Extracted the following community indicators: \n%s\n" % json.dumps(
                    response['reportIndicators'], indent=2))
        except Exception as e:
            print('Could not get submit community report, error: %s' % e)

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        print("Submit New Enclave Incident Report")

        try:
            token = ts.get_token(verify=verify)
            enclave_response = ts.submit_report(token, submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True,
                                                verify=verify)
            print("\tURL: %s\n" % ts.get_report_url(enclave_response['reportId']))

            print(enclave_response)

            if 'reportIndicators' in enclave_response:
                print("Extracted the following enclave indicators: \n%s\n" %
                      json.dumps(enclave_response['reportIndicators'], indent=2))
        except Exception as e:
            print('Could not submit enclave report, error: %s' % e)

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit New Enclave Incident Report with External ID")

        try:
            token = ts.get_token(verify=verify)
            submission_response = ts.submit_report(token, submit_indicators, "Sample SDK Test Report",
                                                   external_id=external_id,
                                                   time_began="2017-02-01T01:23:45", enclave=True, verify=verify)

            print("Report Submitted")
            print("\texternalTrackingId: %s" % submission_response['externalTrackingId'])
            print("\tindicators: %s" % submission_response['reportIndicators'])
            print("\tURL: %s\n" % ts.get_report_url(submission_response['reportId']))
        except Exception as e:
            print('Could not submit report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id:
        print("Get Incident Report By External ID")
        try:
            token = ts.get_token(verify=verify)
            result = ts.get_report_details(token, report_id=external_id, id_type="external", verify=verify)

            print("\ttitle: %s" % result['title'])
            print("\texternalTrackingId: %s" % result['externalTrackingId'])
            print("\tindicators: %s" % result['indicators'])
            print("\tURL: %s\n" % ts.get_report_url(result['id']))
            report_guid = result['id']
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_ext_id:
        print("Update Incident Report By External ID")
        try:
            token = ts.get_token(verify=verify)
            title = "Updated Sample Title"
            body = "updated report body: 21.22.23.24"
            update_response = ts.update_report(token, report_id=external_id, id_type="external", title=title,
                                               report_body=body,
                                               verify=verify)

            print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
            print("\tindicators: %s" % update_response['reportIndicators'])
            print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Incident Report Details by GUID (TruSTAR internal ID)")

        try:
            token = ts.get_token(verify=verify)
            result = ts.get_report_details(token, report_guid, id_type="internal", verify=verify)

            print("\ttitle: %s" % result['title'])
            print("\texternalTrackingId: %s" % result['externalTrackingId'])
            print("\tindicators: %s" % result['indicators'])
            print("\tURL: %s\n" % ts.get_report_url(result['id']))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_guid:
        print("Update Incident Report by GUID (TruSTAR internal ID)")
        try:
            token = ts.get_token(verify=verify)
            title = "New Sample Title"
            body = "new sample body - 7.8.9.10"
            update_response = ts.update_report(token, report_guid, id_type="internal", title=title, report_body=body,
                                               verify=verify)

            print("Updated Report using GUID")
            print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
            print("\tindicators: %s" % update_response['reportIndicators'])
            print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Report by GUID (TruSTAR internal ID)")
        try:
            token = ts.get_token(verify=verify)
            result = ts.get_report_details(token, report_guid, id_type="internal", verify=verify)

            print("\ttitle: %s" % result['title'])
            print("\texternalTrackingId: %s" % result['externalTrackingId'])
            print("\tindicators: %s" % result['indicators'])
            print("\tURL: %s\n" % ts.get_report_url(result['id']))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Release report to community
    if do_release_report_by_ext_id:
        print("Release Incident Report by External ID")
        try:

            token = ts.get_token(verify=verify)
            update_response = ts.update_report(token, report_id=external_id, id_type='external',
                                               distribution="COMMUNITY",
                                               verify=verify)

            print("Report Released using External ID:")
            print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
            print("\tindicators: %s" % update_response['reportIndicators'])
            print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))
        except Exception as e:
            print('Could not release report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id_2:
        print("Get Incident Report Details by External ID")

        try:
            token = ts.get_token(verify=verify)
            result = ts.get_report_details(token, report_id=external_id, id_type="external", verify=verify)

            print("\ttitle: %s" % result['title'])
            print("\texternalTrackingId: %s" % result['externalTrackingId'])
            print("\tindicators: %s" % result['indicators'])
            print("\tURL: %s\n" % ts.get_report_url(result['id']))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Delete test report previously submitted
    if do_delete_report_by_ext_id:
        print("Delete Incident Report by External ID")
        try:
            token = ts.get_token(verify=verify)
            response = ts.delete_report(token, report_id=external_id, id_type="external", verify=verify)
            print("Report Deleted using External ID")

        except Exception as e:
            print('Could not delete report, error: %s' % e)


if __name__ == '__main__':
    main()
