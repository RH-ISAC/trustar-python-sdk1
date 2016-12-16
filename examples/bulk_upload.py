#!/usr/bin/env python

"""
Submit one or more reports from local files (txt, pdf)
"""
from __future__ import print_function

import argparse
import os
import time

from trustar import TruStar


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=(
                                         'Submit one or more reports from local files (txt, pdf, docx, etc) '
                                         'in a directory\n\n'
                                         'Example:\n'
                                         'python bulk_upload.py ./sample_reports'))
    parser.add_argument('dir', help='Path containing report files')
    parser.add_argument('-i', '--ignore', dest='ignore', action='store_true',
                        help='Ignore history and resubmit already procesed files')

    args = parser.parse_args()
    source_report_dir = args.dir

    ts = TruStar(config_role="trustar")
    token = ts.get_token()

    # process all files in directory
    print("Processing and submitting each source file in %s as a TruSTAR Incident Report" % source_report_dir)

    processed_files = set()

    processed_files_file = os.path.join(source_report_dir, "processed_files.log")
    if os.path.isfile(processed_files_file) and not args.ignore:
        processed_files = set(line.strip() for line in open(processed_files_file))

    with open(processed_files_file, 'a', 0) as pf:
        for (dirpath, dirnames, filenames) in os.walk(source_report_dir):
            for source_file in filenames:
                if source_file in processed_files:
                    continue

                print("Processing source file %s " % source_file)
                try:
                    path = os.path.join(source_report_dir, source_file)
                    report_body_txt = ts.process_file(path)

                    # response_json = ts.submit_report(token, report_body_txt, "COMMUNITY: " + file)
                    response_json = ts.submit_report(token, report_body_txt, "ENCLAVE: " + source_file, enclave=True)
                    report_id = response_json['reportId']

                    print("SUCCESSFULLY SUBMITTED REPORT, TRUSTAR REPORT as Incident Report ID %s" % report_id)
                    pf.write("%s\n" % source_file)

                    # if 'reportIndicators' in response_json:
                    #     print("Extracted the following indicators: {}".format(response_json['reportIndicators']))
                    # else:
                    #     print("No indicators returned from  report id {0}".format(report_id))
                    #
                    # # if 'correlatedIndicators' in response_json:
                    #     print(
                    #         "Extracted the following correlated indicators: {}".format(
                    #             response_json['correlatedIndicators']))
                    # else:
                    #     print("No correlatedIndicators found in report id {0}".format(report_id))

                except Exception as e:
                    print("Problem with file %s, exception: %s " % (source_file, e))
                    continue

                time.sleep(2)


if __name__ == '__main__':
    main()
