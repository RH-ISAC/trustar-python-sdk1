#!/usr/bin/env python

"""
Converts each row in a CSV file into an incident report and submits to TruSTAR.

EXAMPLE:
python ingest_csv.py -c "TargetIP,SourceIP,Info,Analysis,Indicators" -t "TrackingNumber" -d "ReportTime" -f  august_incident_report.csv
"""
from __future__ import print_function

import argparse
import json
import time

import pandas as pd
from builtins import range
from builtins import str

from trustar import TruStar

# Set to false to submit to community
do_enclave_submissions = True


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=('Submit TruSTAR reports from a CSV file\n'
                                                  'Example:\n\n'
                                                  'python ingest_csv.py -c "TargetIP,SourceIP,Info,Analysis,Indicators" -t "TrackingNumber" -f  august_incident_report.csv'))
    parser.add_argument('-f', '--file', required=True, dest='file_name', help='csv file to import')
    parser.add_argument('-t', '--title', required=True, dest='title_col', help='Name of column to use as title field')
    parser.add_argument('-d', '--datetime', required=False, dest='datetime_col',
                        help='Name of column to use as report date/time')
    parser.add_argument('-c', '--columns', required=False, dest='cols',
                        help='List of comma-separated column names to include')
    parser.add_argument('-n', '--num-reports', required=False, dest='num_reports', type=int, default=1000,
                        help='Max number of reports to submit (top-down order)')

    args = parser.parse_args()

    allowed_keys_content = []

    if args.cols:
        allowed_keys_content = args.cols.split(",")

    # noinspection PyCallingNonCallable
    ts = TruStar(config_role="trustar")
    token = ts.get_token()

    df = pd.read_csv(args.file_name, nrows=args.num_reports)

    # Create title and report content from the provided column names (if any)
    all_reports = []

    for report_num in range(0, len(df)):
        current_content = ''
        current_title = ''
        current_datetime = None
        current_report = {}
        for key in df:
            #  print(cell_value.isnull())
            # ignore empty cells, which are float64 NaNs
            # if(cell_value.is_null)

            cell_value = df[key][report_num]
            # print(cell_value)
            # if(str(cell_value) == "nan"):
            #     continue

            content = "{}:\n {}\n \n".format(key, cell_value)
            # print(str(df[key][report_num]))
            # if (df[key][report_num]):
            #     # print("key: " + key)
            #     # print("df[key]:" + df[key])
            #     print(str(df[key][report_num]))
            #     print(type(df[key][report_num]))
            if not allowed_keys_content or key in allowed_keys_content:
                current_content += content
            if key == args.title_col:
                current_title = str(df[key][report_num])
            if key == args.datetime_col:
                current_datetime = str(df[key][report_num])

        current_report['reportTitle'] = current_title
        current_report['reportDateTime'] = current_datetime
        current_report['reportContent'] = current_content
        all_reports.append(current_report)

    if do_enclave_submissions:
        num_submitted = 0
        for staged_report in all_reports:

            successful = False
            attempts = 0
            while not successful and attempts < 5:
                attempts += 1
                try:
                    response = ts.submit_report(token, staged_report['reportContent'], staged_report['reportTitle'],
                                                discovered_time_str=staged_report['reportDateTime'],
                                                enclave=True)
                    if 'error' in response:
                        print("Submission failed with error: {}, {}".format(response['error'], response['message']))
                        # if response['message'] == "Access token expired":
                        if response['error'] in (
                                "Internal Server Error", "Access token expired", "Authentication error"):
                            print("Auth token expired, requesting new one")
                            token = ts.get_token()
                        else:
                            raise Exception
                    else:
                        num_submitted += 1
                        successful = True
                        print("Submitted report #{}-{} title {} as TruSTAR IR {}".format(num_submitted, attempts,
                                                                                         staged_report['reportTitle'],
                                                                                         response['reportId']))

                    if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                        print("Extracted the following indicators: {}".format(json.dumps(response['reportIndicators'])))
                    print()
                except Exception as e:
                    print("Problem submitting report: %s" % e)
                    time.sleep(5)

            # Sleep between submissions
            time.sleep(10)


if __name__ == '__main__':
    main()
