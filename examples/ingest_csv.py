#!/usr/bin/env python

"""
Converts each row in a CSV file into an incident report and submits to TruSTAR.
Requirements:
    pip install trustar cef
"""
from __future__ import print_function

from cef import log_cef

import pandas as pd
from builtins import range

from trustar import TruStar

import argparse
import json
import sys
import time
import traceback

import cef

cef._CEF_FORMAT = ('%(date)s %(host)s CEF:%(version)s|%(vendor)s|%(product)s|'
                   '%(device_version)s|%(signature)s|%(name)s|%(severity)s|'
                   'cs1=%(user_agent)s ')

# Set to false to submit to community
do_enclave_submissions = True


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=('Submit TruSTAR reports from a CSV file\n'
                                                  'Example:\n\n'
                                                  'python ingest_csv.py -c "TargetIP,SourceIP,Info,Analysis,Indicators" -t "TrackingNumber" -d "ReportTime" -cn "CaseName" -f reportname.csv'))
    parser.add_argument('-f', '--file', required=True, dest='file_name', help='csv file to import')
    parser.add_argument('-t', '--title', required=True, dest='title_col', help='Name of column to use as title field')
    parser.add_argument('-d', '--datetime', required=False, dest='datetime_col',
                        help='Name of column to use as report date/time')
    parser.add_argument('-c', '--columns', required=False, dest='cols',
                        help='List of comma-separated column names to include')
    parser.add_argument('-n', '--num-reports', required=False, dest='num_reports', type=int, default=1000,
                        help='Max number of reports to submit (top-down order)')
    parser.add_argument('-o', '--output', required=False, dest='cef_output_file', default='trustar.cef',
                        help='Common Event Format (CEF) output log file, one event is generated per successful submission')
    parser.add_argument('-ci', '--case-id', required=False, dest='caseid_col',
                        help='Name of column to use as report case ID for CEF export')
    args = parser.parse_args()

    allowed_keys_content = []

    if args.cols:
        allowed_keys_content = args.cols.split(",")

    ts = TruStar(config_role="trustar")
    token = ts.get_token()

    df = pd.read_csv(args.file_name, nrows=args.num_reports, encoding="latin1")

    # Create title and report content from the provided column names (if any)
    all_reports = []

    for report_num in range(0, len(df)):
        current_content = ''
        current_title = ''
        current_datetime = None
        current_case_id = 0
        current_report = {}

        for key in df:
            # ignore empty cells, which are float64 NaNs
            cell_value = df[key][report_num]

            if pd.isnull(cell_value):
                continue

            cell_value = "%s" % cell_value

            # encode any unicode chars
            string_value = cell_value.encode('utf-8').strip()
            if string_value == "nan":
                print("%s -> %s" % (key, string_value))
                continue

            content = "{}:\n {}\n \n".format(key, string_value)

            if not allowed_keys_content or key in allowed_keys_content:
                current_content += content
            if key == args.title_col:
                current_title = str(df[key][report_num])
            if key == args.datetime_col:
                current_datetime = str(df[key][report_num])
            if key == args.caseid_col:
                current_case_id = str(df[key][report_num])

        current_report['reportTitle'] = current_title
        current_report['reportDateTime'] = current_datetime
        current_report['reportContent'] = current_content
        current_report['reportCaseId'] = current_case_id

        all_reports.append(current_report)

    if do_enclave_submissions:
        num_submitted = 0
        for staged_report in all_reports:

            successful = False
            attempts = 0
            while not successful and attempts < 5:
                attempts += 1
                try:
                    response = ts.submit_report(token, report_body=staged_report['reportContent'],
                                                title=staged_report['reportTitle'],
                                                time_began=staged_report['reportDateTime'], enclave=True)
                    if 'error' in response:
                        print("Submission failed with error: %s, %s" % (response['error'], response['message']))
                        if response['error'] in (
                                "Internal Server Error", "Access token expired", "Authentication error"):
                            print("Auth token expired, requesting new one")
                            token = ts.get_token()
                        else:
                            raise Exception
                    else:
                        num_submitted += 1
                        successful = True

                        print("Submitted report #%s-%s title %s as TruSTAR IR %s with case ID: %s" % (
                            num_submitted, attempts,
                            staged_report['reportTitle'],
                            response['reportId'],
                            staged_report['reportCaseId']))

                        print("URL: %s" % ts.get_report_url(response['reportId']))

                        # Build CEF output:
                        # - HTTP_USER_AGENT is the cs1 field
                        # - example CEF output: CEF:version|vendor|product|device_version|signature|name|severity|cs1=(num_submitted) cs2=(report_url)
                        config = {'cef.version': '0.5', 'cef.vendor': 'TruSTAR',
                                  'cef.device_version': '2.0', 'cef.product': 'API',
                                  'cef': True, 'cef.file': args.cef_output_file}

                        environ = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_HOST': '127.0.0.1',
                                   'HTTP_USER_AGENT': staged_report['reportTitle']}

                        log_cef('SUBMISSION', 1, environ, config, signature="INFO",
                                cs2=staged_report['reportCaseId'],
                                cs3=ts.get_report_url(response['reportId']))

                        ####
                        # TODO: ADD YOUR CUSTOM POST-PROCESSING CODE FOR THIS SUBMISSION HERE
                        ####

                        if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                            print("Indicators:\n %s" % (json.dumps(response['reportIndicators'])))
                        print()

                except Exception as e:
                    traceback.print_exc(file=sys.stdout)
                    print("Problem submitting report: %s" % e)
                    time.sleep(5)

            # Sleep between submissions
            time.sleep(5)


if __name__ == '__main__':
    main()
