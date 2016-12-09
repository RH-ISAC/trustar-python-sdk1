#!/usr/bin/env python

"""
Submit one or more reports from local flat files
"""
from __future__ import print_function

import os
import time

from trustar import TruStar

SOURCE_REPORT_DIR = "./sample_reports"


def main():
    ts = TruStar(config_role="trustar")
    token = ts.get_token()
    # process all files in directory
    print("Processing and submitting each source file in %s as a TruSTAR Incident Report" % SOURCE_REPORT_DIR)
    for (dirpath, dirnames, filenames) in os.walk(SOURCE_REPORT_DIR):
        for file in filenames:
            print("Processing source file %s " % file)
            try:
                path = os.path.join(SOURCE_REPORT_DIR, file)
                report_body_txt = ts.process_file(path)

                #response_json = ts.submit_report(token, report_body_txt, "COMMUNITY: " + file)
                response_json = ts.submit_report(token, report_body_txt, "ENCLAVE: " + file, enclave=True)

                report_id = response_json['reportId']

                print("SUCCESSFULLY SUBMITTED REPORT, TRUSTAR REPORT as Incident Report ID {0}".format(report_id))

                if 'reportIndicators' in response_json:
                    print("Extracted the following indicators: {}".format(response_json['reportIndicators']))
                else:
                    print("No indicators returned from  report id {0}".format(report_id))

                if 'correlatedIndicators' in response_json:
                    print(
                        "Extracted the following correlated indicators: {}".format(
                                response_json['correlatedIndicators']))
                else:
                    print("No correlatedIndicators found in report id {0}".format(report_id))
            except:
                print("Problem with file %s, exception: " % file)
                continue

            time.sleep(2)


if __name__ == '__main__':
    main()
