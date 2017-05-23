#!/usr/bin/env python

"""
Comprehensive script with various TruSTAR API usage examples
"""

from __future__ import print_function
from trustar import TruStar
import json
from random import randint

do_submit_report = False
do_report_details = False
do_update_report = True
do_delete_report = False

# search_string = "1.2.3.4 8.8.8.8 10.0.2.1 185.19.85.172 art-archiv.ru"
search_string = "167.114.35.70,103.255.61.39,miel-maroc.com,malware.exe"
submit_indicators = "google.com malware.exe 103.255.61.39"
submit_indicators_new = "yahoo.com miel-maroc.com 103.255.61.39"


def main():
    ts = TruStar(config_role="localhost")
    token = ts.get_token(verify=False)
    # external_id = str(randint(1, 100))
    external_id = "24"

    # Submit a test report and retrieve it
    if do_submit_report:
        print("Submit Report")
        submission_response = ts.submit_report(token, submit_indicators, "CC REPORT A", external_id=external_id, began_time="2017-02-01T01:23:45",
                                              enclave=True, verify=False)
        print("Report Submitted")
        print("\ttitle: %s" % submission_response['title'])
        print("\texternalTrackingId: %s" % submission_response['externalTrackingId'])
        print("\tindicators: %s" % submission_response['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(submission_response['reportId']))

    # Get test report previously submitted
    if do_report_details:
        print("Get Report")
        result = ts.get_report_details(token, external_id, id_type="external", verify=False)

        print("Report Details")
        print("\ttitle: %s" % result['title'])
        print("\texternalTrackingId: %s" % result['externalTrackingId'])
        print("\tindicators: %s" % result['indicators'])
        print("\tURL: %s\n" % ts.get_report_url(result['reportId']))

    # Update a test report and test with get report
    if do_update_report:
        print("Update Report")
        body = {'incidentReport': {
            'title': "NEW CC REPORT",
            'reportBody': "updated report body - yahoo.com"}}
        update_response = ts.update_report(token, body, external_id, id_type="external", verify=False)
        print (update_response)
        # print("\tReport updated: guid: %s externalTrackingId: %s\n" % update_response['reportId'], update_response['externalTrackingId'])
        # print("Get Updated Report")
        # result = ts.get_report_details(token, report['id'], report['id_type'])

    # Delete test report previously submitted
    if do_delete_report:
        print("Delete Report")
        response = ts.delete_report(token, submit_indicators, "ENCLAVE API SUBMISSION TEST ", enclave=True)
        print("Report deleted")


if __name__ == '__main__':
    main()
