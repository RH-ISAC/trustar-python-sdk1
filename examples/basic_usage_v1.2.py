#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function
from trustar import TruStar
import json
from random import randint

do_submit_report = True
do_report_details1 = True
do_update_report = True
do_report_details2 = True
do_release_report = True
do_report_details3 = True
do_delete_report = True

search_string = "167.114.35.70,103.255.61.39,miel-maroc.com,malware.exe"
submit_indicators = "google.com malware.exe 103.255.61.39"

verify = True

def main():
    ts = TruStar(config_role="demo")
    token = ts.get_token(verify=verify)
    external_id = str(randint(1, 100))
    # external_id = "320"

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit Report")
        submission_response = ts.submit_report_v12(token, submit_indicators, "CC REPORT A", external_id=external_id,
                                                   began_time="2017-02-01T01:23:45", enclave=True, verify=verify)

        print("Report Submitted")
        print("\texternalTrackingId: %s" % submission_response['externalTrackingId'])
        print("\tindicators: %s" % submission_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(submission_response['reportId']))

    # Get test report previously submitted
    if do_report_details1:
        print("Get Report")
        result = ts.get_report_details_v12(token, external_id, id_type="external", verify=verify)

        print("Report Details")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Update a test report and test with get report
    if do_update_report:
        print("Update Report")
        title = "NEW CC REPORT"
        body = "updated report body - yahoo.com"
        update_response = ts.update_report(token, external_id, id_type="external", title=title, report_body=body, verify=verify)

        print("Updated Report")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details2:
        print("Get Report")
        result = ts.get_report_details_v12(token, external_id, id_type="external", verify=verify)

        print("Report Details")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Release report to community
    if do_release_report:
        print("Release Report")
        update_response = ts.update_report(token, external_id, id_type='external', distribution="COMMUNITY", verify=verify)

        print("Report Released")
        print("\texternalTrackingId: %s" % update_response['externalTrackingId'])
        print("\tindicators: %s" % update_response['reportIndicators'])
        print("\tURL: %s\n" % ts.get_report_url(update_response['reportId']))

    # Get test report previously submitted
    if do_report_details3:
        print("Get Report")
        result = ts.get_report_details_v12(token, external_id, id_type="external", verify=verify)

        print("Report Details")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['id']))

    # Delete test report previously submitted
    if do_delete_report:
        print("Delete Report")
        response = ts.delete_report(token, external_id, id_type="external", verify=verify)
        print("Report Deleted")


if __name__ == '__main__':
    main()
