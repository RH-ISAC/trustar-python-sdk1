#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function

import json
import sys
import time
from random import randint

from trustar import TruStar, DISTRIBUTION_TYPE_COMMUNITY, DISTRIBUTION_TYPE_ENCLAVE, Report


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
search_string = ','.join([
    "167.114.35.70",
    "103.255.61.39",
    "miel-maroc.com",
    "malware.exe"
])

submit_indicators = ' '.join([
    "google.com",
    "malware.exe",
    "103.255.61.39"
])


def to_milliseconds(days):
    """
    :return: the number of days expressed as milliseconds. e.g to_milliseconds(1) -> 86400
    """
    return days * 24 * 60 * 60 * 1000


def main():

    role = "trustar"
    if len(sys.argv) > 1:
        role = sys.argv[1]

    ts = TruStar(config_file="trustar.conf", config_role=role)

    # generate random id to use as external_id
    external_id = str(randint(1, 100000))

    # or use a specific external_id
    # external_id = "321"

    report_guid = None
    current_time = int(time.time()) * 1000
    yesterday_time = current_time - to_milliseconds(days=1)

    if do_latest_reports:

        print("Getting Latest Accessible Incident Reports Since 24 hours ago ...")
        try:
            reports = ts.get_report_generator(from_time=yesterday_time, to_time=current_time)

            print("Got %s results" % len(reports))

            for report in reports:
                print(report)
            print()

        except Exception as e:
            print('Could not get latest reports, error: %s' % e)

    if do_reports_by_community:

        two_days_ago = current_time - to_milliseconds(days=2)

        print("Getting community only reports for the previous day ...")
        try:
            reports = ts.get_report_generator(from_time=two_days_ago,
                                              to_time=yesterday_time,
                                              distribution_type=DISTRIBUTION_TYPE_COMMUNITY)

            print("Got %s results" % len(reports))

            for report in reports:
                print(report)
            print()

        except Exception as e:
            print('Could not get community reports, error: %s' % e)

    if do_reports_by_enclave:

        a_week_ago = current_time - to_milliseconds(days=7)

        print("Getting enclave only reports for the previous week ...")
        try:
            reports = ts.get_report_generator(from_time=a_week_ago,
                                              to_time=current_time,
                                              distribution_type=DISTRIBUTION_TYPE_ENCLAVE,
                                              enclave_ids=ts.enclave_ids)

            print("Got %s results" % len(reports))

            for result in reports:
                print(result)
            print()

        except Exception as e:
            print('Could not get community reports, error: %s' % e)

    if do_correlated:
        print("Querying Accessible Correlated Reports...")
        try:
            report_ids = ts.get_correlated_reports(search_string)

            print(report_ids)
            print("%d report(s) correlated with indicators '%s':\n" % (len(report_ids), search_string))
            print("\n".join(report_ids))
            print()
        except Exception as e:
            print('Could not get correlated reports, error: %s' % e)

    # if do_latest_indicators:
    #     print("Get Latest Indicators (first 100)")
    #
    #     try:
    #         results = ts.query_latest_indicators(source='INCIDENT_REPORT', indicator_types='ALL',
    #                                              interval_size=24,
    #                                              limit=100)
    #         if 'indicators' in results:
    #             for ioc_type, value in results['indicators'].items():
    #                 if len(value) > 0:
    #                     print("\t%s:  %s" % (ioc_type, ','.join(value)))
    #             print()
    #     except Exception as e:
    #         print('Could not get latest indicators, error: %s' % e)

    if do_community_trends:
        print("Get community trends")

        try:
            results = ts.get_community_trends_generator(indicator_type=None, from_time=yesterday_time, to_time=current_time)
            for result in results:
                print(result)
        except Exception as e:
            print('Could not get community trends, error: %s' % e)

    if do_query_indicators:
        try:
            indicators = ts.get_related_indicators_generator(indicators=search_string)
            print("Got %s results" % len(indicators))
            for indicator in indicators:
                print(indicator)
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
                print("Extracted the following community indicators: \n%s\n"
                      % json.dumps(response.get('reportIndicators'), indent=2))
        except Exception as e:
            print('Could not submit community report, error: %s' % e)

    # Submit simple test report to your enclave
    if do_enclave_submissions:
        print("Submit New Enclave Incident Report")

        try:
            response = ts.submit_report(submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True)
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))

            print(response)

            if 'reportIndicators' in response:
                print("Extracted the following enclave indicators: \n%s\n"
                      % json.dumps(response.get('reportIndicators'), indent=2))
        except Exception as e:
            print('Could not submit enclave report, error: %s' % e)

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit New Enclave Incident Report with External ID")

        try:
            response = ts.submit_report(submit_indicators, "Sample SDK Test Report",
                                        external_id=external_id,
                                        time_began="2017-02-01T01:23:45", enclave=True)

            print("Report Submitted")
            print("\texternalTrackingId: %s" % response.get('externalTrackingId'))
            print("\tindicators: %s" % response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))
        except Exception as e:
            print('Could not submit report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id:
        print("Get Incident Report By External ID")
        try:
            report = ts.get_report_details(report_id=external_id, id_type="external")

            print("\ttitle: %s" % report.title)
            print("\texternalTrackingId: %s" % report.external_id)
            print("\tindicators: %s" % report.indicators)
            print("\tURL: %s\n" % ts.get_report_url(report.id))
            report_guid = report.id
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_ext_id:
        print("Update Incident Report By External ID")
        try:
            title = "Updated Sample Title"
            body = "updated report body: 21.22.23.24"
            response = ts.update_report(report_id=external_id, id_type=Report.ID_TYPE_EXTERNAL, title=title,
                                        report_body=body)

            print("\texternalTrackingId: %s" % response.get('externalTrackingId'))
            print("\tindicators: %s" % response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Incident Report Details by GUID (TruSTAR internal ID)")

        try:
            report = ts.get_report_details(report_guid, id_type="internal")

            print("\ttitle: %s" % report.title)
            print("\texternalTrackingId: %s" % report.external_id)
            print("\tindicators: %s" % report.indicators)
            print("\tURL: %s\n" % ts.get_report_url(report.id))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Update a test report and test with get report
    if do_update_report_by_guid:
        print("Update Incident Report by GUID (TruSTAR internal ID)")
        try:
            title = "New Sample Title"
            body = "new sample body - 7.8.9.10"
            response = ts.update_report(report_guid, id_type="internal", title=title, report_body=body)

            print("Updated Report using GUID")
            print("\texternalTrackingId: %s" % response.get('externalTrackingId'))
            print("\tindicators: %s" % response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))
        except Exception as e:
            print('Could not update report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Report by GUID (TruSTAR internal ID)")
        try:
            report = ts.get_report_details(report_guid, id_type="internal")

            print("\ttitle: %s" % report.title)
            print("\texternalTrackingId: %s" % report.external_id)
            print("\tindicators: %s" % report.indicators)
            print("\tURL: %s\n" % ts.get_report_url(report.id))
        except Exception as e:
            print('Could not get report, error: %s' % e)

    # Release report to community
    if do_release_report_by_ext_id:
        print("Release Incident Report by External ID")
        try:

            response = ts.update_report(report_id=external_id, id_type='external',
                                               distribution_type="COMMUNITY")

            print("Report Released using External ID:")
            print("\texternalTrackingId: %s" % response.get('externalTrackingId'))
            print("\tindicators: %s" % response.get('reportIndicators'))
            print("\tURL: %s\n" % ts.get_report_url(response.get('reportId')))
        except Exception as e:
            print('Could not release report, error: %s' % e)

    # Get test report previously submitted
    if do_report_details_by_ext_id_2:
        print("Get Incident Report Details by External ID")

        try:
            report = ts.get_report_details(report_id=external_id, id_type="external")

            print("\ttitle: %s" % report.title)
            print("\texternalTrackingId: %s" % report.external_id)
            print("\tindicators: %s" % report.indicators)
            print("\tURL: %s\n" % ts.get_report_url(report.id))
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
            report = ts.get_report_details(report_id=report_id)
            enclave_id = report.enclave_ids[0]

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

            # List all enclave tags
            result = ts.get_all_enclave_tags(enclave_ids=ts.enclave_ids)
            print("List of enclave tags for enclave %s\n" % enclave_id)
            print(json.dumps(result, indent=2))

            # Search report by tag
            reports = ts.get_report_generator(from_time=yesterday_time,
                                              to_time=current_time,
                                              enclave_ids=ts.enclave_ids,
                                              tag="triage")
            print("Got %s results" % len(reports))

            for report in reports:
                print(report)
            print()

        except Exception as e:
            print('Could not handle enclave tag operation, error: %s' % e)


if __name__ == '__main__':
    main()
