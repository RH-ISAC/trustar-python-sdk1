#!/usr/bin/env python

"""
Process a FireEye alerts file and convert each row to an incident report and submitting to TruSTAR:

"""

import pandas as pd
import time
import json

from trustar import TruStar
# Set to false to submit to community
do_enclave_submissions = True

def filter(df):
    """
    method that takes in FireEye (FE) alerts and filters FE-tests and False Positives
    :param df:
    :return:
    """
    result = []
    for o in df['alerts']:
        if 'closedState' in o:
            if o['closedState'] != 'False Positive':
                if 'distinguishers' in o:
                    try:
                        if 'virus' in o['distinguishers']:
                            if o['distinguishers']['virus'] != 'fetestevent':
                                result.append(o)
                        else:
                            result.append(o)
                    except TypeError:
                        result.append(o)
                else:
                    result.append(o)
        else:
            if 'distinguishers' in o:
                try:
                    if 'virus' in o['distinguishers']:
                        if o['distinguishers']['virus'] != 'fetestevent':
                            result.append(o)
                    else:
                        result.append(o)
                except TypeError:
                    result.append(o)
                else:
                    result.append(o)
    return result


def main():
    ts = TruStar()
    token = ts.get_token()

    df = pd.read_json('bulk_upload.csv') # Pandas dataframe

    filtered_data = filter(df)

    all_reports = []
    for alert in filtered_data:
        title = str(alert['message'].encode('utf-8')) + ' ' + str(alert['displayId'])
        content = ""
        for key in alert:
            type_value = type(alert[key])
            if type_value == list or type_value == int or type_value == long or type_value == bool \
                    or type_value == dict or alert[key] is None:
                content += key + ': ' + str(alert[key]) + '\n'
            else:
                content += key + ': ' + str(alert[key].encode('ascii', 'ignore')) + '\n'
        created_time = str(alert['createDate'])
        current_report = {'reportTitle': title, 'reportContent': content, 'created_time': created_time}
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
