#!/usr/bin/env python

"""
Process a CSV file and convert each row to an incident report and submitting to TruSTAR:

EXAMPLE
python ingest_csv.py -c "TargetIP,SourceIP,Info,Analysis,Indicators" -t "TrackingNumber" -f  august_incident_report.csv
"""

import argparse
import json
import pandas as pd
import time

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
    parser.add_argument('-c', '--columns', required=False, dest='cols',
                        help='List of comma-separated column names to include')
    args = parser.parse_args()

    allowed_keys_content = []

    if args.cols:
        allowed_keys_content = args.cols.split(",")

    # noinspection PyCallingNonCallable
    ts = TruStar()
    token = ts.get_token()

    df = pd.read_csv(args.file_name)

    # Create title and report content from the provided column names (if any)
    all_reports = []

    for report_num in xrange(0, len(df)):
        current_content = ''
        current_title = ''
        current_report = {}
        for key in df:
            # content = key + ':' + '\n ' + str(df[key][report_num]) + '\n '
            content = "{}:\n {}\n ".format(key, str(df[key][report_num]))

            if not allowed_keys_content or key in allowed_keys_content:
                current_content += content
            if key == args.title_col:
                current_title = str(df[key][report_num])
        current_report['reportTitle'] = current_title
        current_report['reportContent'] = current_content
        all_reports.append(current_report)

    if do_enclave_submissions:
        for staged_report in all_reports:
            response = ts.submit_report(token, staged_report['reportContent'], staged_report['reportTitle'],
                                        enclave=True)
            if not 'reportId' in response:
                print "Error: {}, {}".format(response['error'], response['message'])
                break
            else:
                print    "Submitted report title {} as TruSTAR IR {}".format(staged_report['reportTitle'],
                                                                          response['reportId'])
            if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                print("Extracted the following indicators: {}".format(json.dumps(response['reportIndicators'])))
            print
            time.sleep(3)


if __name__ == '__main__':
    main()
