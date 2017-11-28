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
do_community_trends = True
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
do_add_enclave_tag = True
do_delete_enclave_tag = True
do_get_enclave_tags = True
do_reports_by_community = True
do_reports_by_enclave = True
do_reports_mine = True

# search_string = "1.2.3.4 8.8.8.8 10.0.2.1 185.19.85.172 art-archiv.ru"
search_string = "167.114.35.70,103.255.61.39,miel-maroc.com,malware.exe"
submit_indicators = "google.com malware.exe 103.255.61.39"


def to_seconds(days):
    """
    :return: the number of days expressed as seconds. e.g to_seconds(1) -> 86400
    """

    return days * 24 * 60 * 60


def main():
    role = "staging"
    if len(sys.argv) > 1:
        role = sys.argv[1]

    ts = TruStar(config_role=role)

    # generate random id to use as external_id
    external_id = str(randint(1, 100000))

    # or use a specific external_id
    # external_id = "321"

    report_guid = None
    current_time = int(time.time())
    yesterday_time = current_time - to_seconds(days=1)

    if do_latest_reports:

        print("Getting Latest Accessible Incident Reports Since 24 hours ago ...")
        try:
            results = ts.get_reports(from_time=yesterday_time, to_time=current_time)

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

    if do_reports_by_community:

        two_days_ago = current_time - to_seconds(days=2)

        print("Getting community only reports for the previous day ...")
        try:
            results = ts.get_reports(from_time=two_days_ago, to_time=yesterday_time,
                                     distribution_type='COMMUNITY')

            print("Got %s results" % (results.get('totalElements')))

            for result in results.get('data').get('reports'):
                print(result)
            print()

        except Exception as e:
            print('Could not get community reports, error: %s' % e)

    if do_reports_by_enclave:

        a_week_ago = current_time - to_seconds(days=7)

        print("Getting enclave only reports for the previous week ...")
        try:
            results = ts.get_reports(from_time=a_week_ago, to_time=current_time, distribution_type='ENCLAVE',
                                     enclave_ids=ts.get_enclave_ids())

            print("Got %s results" % (results.get('totalElements')))

            for result in results.get('data').get('reports'):
                print(result)
            print()

        except Exception as e:
            print('Could not get community reports, error: %s' % e)

    if do_reports_mine:

        a_week_ago = current_time - to_seconds(days=7)

        print("Getting my reports for the previous week ...")
        try:
            results = ts.get_reports(from_time=a_week_ago, to_time=current_time, submitted_by="me")

            print("Got %s results" % (results.get('totalElements')))

            for result in results.get('data').get('reports'):
                print(result)
            print()

        except Exception as e:
            print('Could not get community reports, error: %s' % e)
    if do_correlated:
        print("Querying Accessible Correlated Reports...")
        try:
            results = ts.get_correlated_reports(search_string)

            print(results)
            print("%d report(s) correlated with indicators '%s':\n" % (len(results), search_string))
            print("\n".join(results))
            print()
        except Exception as e:
            print('Could not get correlated reports, error: %s' % e)

    if do_latest_indicators:
        print("Get Latest Indicators (first 100)")

        try:
            results = ts.query_latest_indicators(source='INCIDENT_REPORT', indicator_types='ALL',
                                                 interval_size=24,
                                                 limit=100)
            if 'indicators' in results:
                for ioc_type, value in results['indicators'].items():
                    if len(value) > 0:
                        print("\t%s:  %s" % (ioc_type, ','.join(value)))
                print()
        except Exception as e:
            print('Could not get latest indicators, error: %s' % e)

    if do_community_trends:
        print("Get community trends")

        try:
            results = ts.get_community_trends(type='other',
                                              from_time=yesterday_time,
                                              to_time=current_time,
                                              page_size=5,
                                              start_page=0)
            print(results)
        except Exception as e:
            print('Could not get community trends, error: %s' % e)

    if do_query_indicators:
        print("Querying Correlated Indicators with Search String '%s' (first 100)" % search_string)
        try:
            results = ts.query_indicators(search_string, '100')

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
            response = ts.submit_report(submit_indicators, "COMMUNITY API SUBMISSION TEST",
                                        time_began="2017-02-01T01:23:45")
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))

            if 'reportIndicators' in response:
                print("Extracted the following community indicators: \n%s\n" % json.dumps(
                    response.get('reportIndicators'), indent=2))
        except Exception as e:
            print('Could not submit community report, error: %s' % e)

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        print("Submit New Enclave Incident Report")

        try:
            enclave_response = ts.submit_report(submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True)
            print("\tURL: %s\n" % ts.get_report_url(enclave_response.get('reportId')))

            print(enclave_response)

            if 'reportIndicators' in enclave_response:
                print("Extracted the following enclave indicators: \n%s\n" %
                      json.dumps(enclave_response.get('reportIndicators'), indent=2))
        except Exception as e:
            print('Could not submit enclave report, error: %s' % e)

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit New Enclave Incident Report with External ID")

        try:
            submission_response = ts.submit_report(submit_indicators, "Sample SDK Test Report",
                                                   external_id=external_id,
                                                   time_began="2017-02-01T01:23:45", enclave=True)

            print("Report Submitted")
            print("\texternalTrackingId: %s" % submission_response.get('externalTrackingId'))
            print("\tindicators: %s" % submission_response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(submission_response.get('reportId')))
        except Exception as e:
            print('Could not submit report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id:
        print("Get Incident Report By External ID")
        try:
            result = ts.get_report_details(report_id=external_id, id_type="external")

            print("\ttitle: %s" % result.get('title'))
            print("\texternalTrackingId: %s" % result.get('externalTrackingId'))
            print("\tindicators: %s" % result.get('indicators'))
            print("\tURL: %s\n" % ts.get_report_url(result.get('id')))
            report_guid = result.get('id')
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_ext_id:
        print("Update Incident Report By External ID")
        try:
            title = "Updated Sample Title"
            body = "updated report body: 21.22.23.24"
            update_response = ts.update_report(report_id=external_id, id_type="external", title=title,
                                               report_body=body)

            print("\texternalTrackingId: %s" % update_response.get('externalTrackingId'))
            print("\tindicators: %s" % update_response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(update_response.get('reportId')))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Incident Report Details by GUID (TruSTAR internal ID)")

        try:
            result = ts.get_report_details(report_guid, id_type="internal")

            print("\ttitle: %s" % result.get('title'))
            print("\texternalTrackingId: %s" % result.get('externalTrackingId'))
            print("\tindicators: %s" % result.get('indicators'))
            print("\tURL: %s\n" % ts.get_report_url(result.get('id')))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_guid:
        print("Update Incident Report by GUID (TruSTAR internal ID)")
        try:
            title = "New Sample Title"
            body = "new sample body - 7.8.9.10"
            update_response = ts.update_report(report_guid, id_type="internal", title=title, report_body=body)

            print("Updated Report using GUID")
            print("\texternalTrackingId: %s" % update_response.get('externalTrackingId'))
            print("\tindicators: %s" % update_response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(update_response.get('reportId')))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Report by GUID (TruSTAR internal ID)")
        try:
            result = ts.get_report_details(report_guid, id_type="internal")

            print("\ttitle: %s" % result['title'])
            print("\texternalTrackingId: %s" % result.get('externalTrackingId'))
            print("\tindicators: %s" % result.get('indicators'))
            print("\tURL: %s\n" % ts.get_report_url(result.get('id')))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Release report to community
    if do_release_report_by_ext_id:
        print("Release Incident Report by External ID")
        try:

            update_response = ts.update_report(report_id=external_id, id_type='external',
                                               distribution="COMMUNITY")

            print("Report Released using External ID:")
            print("\texternalTrackingId: %s" % update_response.get('externalTrackingId'))
            print("\tindicators: %s" % update_response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(update_response.get('reportId')))
        except Exception as e:
            print('Could not release report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id_2:
        print("Get Incident Report Details by External ID")

        try:
            result = ts.get_report_details(report_id=external_id, id_type="external")

            print("\ttitle: %s" % result.get('title'))
            print("\texternalTrackingId: %s" % result.get('externalTrackingId'))
            print("\tindicators: %s" % result.get('indicators'))
            print("\tURL: %s\n" % ts.get_report_url(result.get('id')))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Delete test report previously submitted
    if do_delete_report_by_ext_id:
        print("Delete Incident Report by External ID")
        try:
            response = ts.delete_report(report_id=external_id, id_type="external")
            print("Report Deleted using External ID\n")

        except Exception as e:
            print('Could not delete report, error: %s' % e)

    # Add an enclave tag to a newly created report
    if do_add_enclave_tag:
        print("Add enclave tag to incident report")

        try:
            # submit report
            response = ts.submit_report(submit_indicators, "Enclave report with tag", enclave=True)
            report_id = response.get('reportId')
            print("\tId of new report %s\n" % report_id)

            # get back report details, including the enclave it's in
            response = ts.get_report_details(report_id=report_id)
            enclave_list = list(response.get('enclaves'))
            enclave_id = enclave_list.pop(0).get('id')

            # add an enclave tag
            response = ts.add_enclave_tag(report_id=report_id, name="triage", enclave_id=enclave_id)
            # print the added enclave tag
            print(response)
            print("\tId of new enclave tag %s\n" % response.get('guid'))

            # add another enclave tag
            response = ts.add_enclave_tag(report_id=report_id, name="resolved", enclave_id=enclave_id)
            # print the added enclave tag
            print(response)
            print("\tId of new enclave tag %s\n" % response.get('guid'))

            # Get enclave tag info
            if do_get_enclave_tags:
                print("Get enclave tags for report")
                response = ts.get_enclave_tags(report_id)
                print("\tEnclave tags for report %s\n" % report_id)
                print(json.dumps(response, indent=2))

            # delete enclave tag by name
            if do_delete_enclave_tag:
                print("Delete enclave tag from report")
                response = ts.delete_enclave_tag(report_id, name="triage", enclave_id=enclave_id)
                print("\tDeleted enclave tag for report %s\n" % report_id)
                print(response)

            # add it back
            ts.add_enclave_tag(report_id=report_id, name="triage", enclave_id=enclave_id)

        except Exception as e:
            print('Could not handle enclave tag operation, error: %s' % e)


if __name__ == '__main__':
    main()
