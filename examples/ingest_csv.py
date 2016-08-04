#!/usr/bin/env python

"""
Process a CSV file and convert each row to an incident report and submitting to TruSTAR
"""

import pandas as pd

from trustar import TruStar

fileName = 'Report1.csv'

do_enclave_submissions = True

allowedKeysContent = ['Analysis', 'Destination Information', 'Source Information', 'Recorded Data', 'Conclusions']
allowedKeysTitle = ['Display ID']

ts = TruStar()
token = ts.get_token()


def main():
    df = pd.read_csv(fileName)

    # Total number of rows
    numberOfRows = len(df)

    # Create title and report content from the provided column names (if any)
    allReports = []

    for report_num in xrange(0, numberOfRows):
        currentContent = ''
        currentTitle = ''
        currentReport = {}
        for key in df:
            content = key + ':' + '\n ' + str(df[key][report_num]) + '\n '
            if key in allowedKeysContent:
                currentContent += content
            if key in allowedKeysTitle:
                currentTitle = str(df[key][report_num])
        currentReport['reportTitle'] = currentTitle
        currentReport['reportContent'] = currentContent
        allReports.append(currentReport)

    if do_enclave_submissions:
        for staged_report in allReports:
            response = ts.submit_report(token, staged_report['reportContent'], staged_report['reportTitle'],
                                        enclave=True)
            if not 'reportId' in response:
                print "Error: {}, {}".format(response['error'], response['message'])
                break
            else:
                print "Submitted report {} as TruSTAR IR {}".format(staged_report['reportTitle'],
                                                                    response['reportId'])
            if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                print("Extracted the following indicators: {}".format(response['reportIndicators']))
            print


if __name__ == '__main__':
    main()
