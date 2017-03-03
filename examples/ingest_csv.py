#!/usr/bin/env python

"""
Converts each row in a CSV file into an incident report and submits to TruSTAR.

Requirements:
    pip install trustar cef
"""
from __future__ import print_function

import argparse
import json
import time

import cef

cef._CEF_FORMAT = ('%(date)s %(host)s CEF:%(version)s|%(vendor)s|%(product)s|'
                   '%(device_version)s|%(signature)s|%(name)s|%(severity)s|'
                   'cs1=%(user_agent)s ')

from cef import log_cef

import pandas as pd
from builtins import range
from builtins import str

from trustar import TruStar
import numpy as np

# Set to false to submit to community
do_enclave_submissions = True


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=('Submit TruSTAR reports from a CSV file\n'
                                                  'Example:\n\n'
                                                  'python ingest_csv.py -c "TargetIP,SourceIP,Info,Analysis,Indicators" -t "TrackingNumber" -d "ReportTime"  -f  august_incident_report.csv'))
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
                                                began_time_str=staged_report['reportDateTime'],
                                                enclave=True)
                    # noinspection PyPep8
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
                        print("Submitted report #%s-%s title %s as TruSTAR IR %s" % (num_submitted, attempts,
                                                                                     staged_report['reportTitle'],
                                                                                     response['reportId']))
                        print("URL: %s" % ts.get_report_url(response['reportId']))

                        # HTTP_USER_AGENT is the cs1 field
                        # example CEF output: CEF:version|vendor|product|device_version|signature|name|severity|cs1=(num_submitted) cs2=(report_url)

                        config = {'cef.version': '0.5', 'cef.vendor': 'TruSTAR',
                                  'cef.device_version': '2.0', 'cef.product': 'API',
                                  'cef': True, 'cef.file': args.cef_output_file}
                        environ = {'REMOTE_ADDR': '127.0.0.1', 'HTTP_HOST': '127.0.0.1',
                                   'HTTP_USER_AGENT': num_submitted}

                        log_cef('SUBMISSION', 1, environ, config, signature="INFO",
                                cs2=ts.get_report_url(response['reportId']))

                        # Static CEF message - alternative solution
                        # CEFMessage ="CEF:0.5|TruSTAR|API|2.0|INFO|SUBMISSION|1|cs1=%s cs2=%s" %(num_submitted,ts.get_report_url(response['reportId']))

                        # CHANGE CEF OUTPUT FILE LOCATION HERE:
                        # cef_file = open('CEFoutput.cef','a')
                        # cef_file.write("\n" + CEFMessage + "\n")
                        # cef_file.close()

                        ####
                        # TODO: ADD YOUR CUSTOM POST-PROCESSING CODE FOR THIS SUBMISSION HERE
                        ####

                    if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                        print("Indicators:\n %s" % (json.dumps(response['reportIndicators'])))
                    print()
                except Exception as e:
                    print("Problem submitting report: %s" % e)
                    time.sleep(5)

            # Sleep between submissions
            time.sleep(5)


if __name__ == '__main__':
    main()
