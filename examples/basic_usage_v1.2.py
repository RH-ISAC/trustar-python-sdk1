#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function
from trustar import TruStar
import json
from random import randint

do_submit_report = True
do_report_details_by_ext_id = True
do_update_report_by_ext_id = True
do_report_details_by_guid = True
do_update_report_by_guid = True
do_release_report_by_ext_id = True
do_report_details_by_ext_id_2 = True
do_delete_report_by_ext_id = True

submit_indicators = "google.com malware.exe 103.255.61.39"

verify = True

def main():
    ts = TruStar(config_role="trustar")
    token = ts.get_token(verify=verify)

    # generate random id to use as external_id
    external_id = str(randint(1, 100))

    # or use a specific external_id
    # external_id = "321"
    report_guid = None

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit Report")
        submission_response = ts.submit_report_v12(token, submit_indicators, "Sample SDK Test Report", external_id=external_id,
                                                   began_time="2017-02-01T01:23:45", enclave=True, verify=verify)

        print("Report Submitted")
        print("\texternalTrackingId: %s" % submission_response['externalTrackingId'])
        print("\tindicators: %s" % submission_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(submission_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_ext_id:
        print("Get Report")
        result = ts.get_report_details_v12(token, external_id, id_type="external", verify=verify)

        print("Report Details using External ID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))
        report_guid = result['id'];

    # Update a test report and test with get report
    if do_update_report_by_ext_id:
        print("Update Report")
        title = "NEW CC REPORT"
        body = "updated report body: 21.22.23.24"
        update_response = ts.update_report(token, external_id, id_type="external", title=title, report_body=body, verify=verify)

        print("Updated Report using External ID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Report")
        result = ts.get_report_details_v12(token, report_guid, id_type="internal", verify=verify)

        print("Report Details using Guid")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Update a test report and test with get report
    if do_update_report_by_guid:
        print("Update Report")
        title = "New Sample Title"
        body = "new sample body - 7.8.9.10"
        update_response = ts.update_report(token, report_guid, id_type="internal", title=title, report_body=body, verify=verify)

        print("Updated Report using GUID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_guid:
        print("Get Report")
        result = ts.get_report_details_v12(token, report_guid, id_type="internal", verify=verify)

        print("Report Details using GUID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Release report to community
    if do_release_report_by_ext_id:
        print("Release Report")
        update_response = ts.update_report(token, external_id, id_type='external', distribution="COMMUNITY", verify=verify)

        print("Report Released using External ID")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details_by_ext_id_2:
        print("Get Report")
        result = ts.get_report_details_v12(token, external_id, id_type="external", verify=verify)

        print("Report Details using External ID")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Delete test report previously submitted
    if do_delete_report_by_ext_id:
        print("Delete Report")
        response = ts.delete_report(token, external_id, id_type="external", verify=verify)
        print("Report Deleted using External ID")


if __name__ == '__main__':
    main()
