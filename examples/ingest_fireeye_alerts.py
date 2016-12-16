#!/usr/bin/env python

from __future__ import print_function

"""
Process a FireEye alerts API export csv and convert each row to an incident report and submitting to TruSTAR:

"""
import json
import sys
import time

import pandas as pd

from trustar import TruStar

# Set to false to submit to community
do_enclave_submissions = True


def filter_false_positive(df, process_time):
    """
    method that takes in FireEye (FE) alerts and filters FE-tests and False Positives
    :param process_time:
    :param df:
    :return:
    """
    result = []
    track = []
    count = 0
    for o in df['alerts']:
        count += 1
        if 'closedState' in o:
            if o['closedState'] != 'False Positive':
                if 'distinguishers' in o:
                    try:
                        if 'virus' in o['distinguishers']:
                            if o['distinguishers']['virus'] != 'fetestevent':
                                result.append(o)
                            else:
                                track.append(o)  # Track fetestevents that are skipped
                        else:
                            result.append(o)
                    except TypeError:
                        result.append(o)
                else:
                    result.append(o)
            else:
                track.append(o)  # Track false positives that are skipped
        elif 'distinguishers' in o:
            try:
                if 'virus' in o['distinguishers']:
                    if o['distinguishers']['virus'] != 'fetestevent':
                        result.append(o)
                    else:
                        track.append(o)  # Track fetestevents that are skipped
                else:
                    result.append(o)
            except TypeError:
                result.append(o)

    trackfile = open('tracking_fetest_' + process_time + '.txt', 'w')
    numskip = 1
    for item in track:
        trackfile.write("\n\n**** {:d}: Display ID {} ****\n\n{}".format(numskip, item['displayId'], item))
        numskip += 1
    return result


def filter_win_methodology(df, process_time):
    """
    A function that filters out the windows methodology alert data obtained from FireEye
    :param df: a DataFrame object
    :param process_time:
    :return:
    """
    result = []
    track = []
    for o in df:
        if 'WINDOWS METHODOLOGY' in o['message']:
            track.append(o)
        else:
            result.append(o)
    trackfile = open('tracking_winMethodology_' + process_time + '.txt', 'w')
    numskip = 1
    for item in track:
        trackfile.write("\n\n**** {:d}: Display ID {} ****\n\n{}".format(numskip, item['displayId'], item))
        numskip += 1
    return result


def filter_bash_shellshock(df, process_time):
    """
    A function that filters out the BASH SHELLSHOCK alert data obtained from FireEye
    :param df: a DataFrame object
    :param process_time:
    :return:
    """
    result = []
    track = []
    for o in df:
        if 'BASH [Shellshock HTTP]' in o['message']:
            track.append(o)
        else:
            result.append(o)
    trackfile = open('tracking_bashShellShock_' + process_time + '.txt', 'w')
    numskip = 1
    for item in track:
        trackfile.write("\n\n**** {:d}: Display ID {} ****\n\n{}".format(numskip, item['displayId'], item))
        numskip += 1
    return result


def filter_webapp_attack(df, process_time):
    """
    A function that filters out the BASH SHELLSHOCK alert data obtained from FireEye
    :param df: a DataFrame object
    :param process_time:
    :return:
    """
    result = []
    track = []
    for o in df:
        if 'METHODOLOGY - WEB APP ATTACK' in o['message']:
            track.append(o)
        else:
            result.append(o)
    trackfile = open('tracking_webAppAttack_' + process_time + '.txt', 'w')
    numskip = 1
    for item in track:
        trackfile.write("\n\n**** {:d}: Display ID {} ****\n\n{}".format(numskip, item['displayId'], item))
        numskip += 1
    return result


def process_alert(file_name):
    """
    A function that removes the alerts property from the FireEye alert and transform the data into a JSON ready format
    :param file_name:
    :return:
    """

    processed_line = open(file_name, 'r').read()
    char_pos = processed_line.find("}")
    new_line = "{" + processed_line[char_pos + 2:]
    return new_line


def main(inputfile):
    ts = TruStar()
    token = ts.get_token()

    df = pd.read_json(process_alert(inputfile))

    process_time = time.strftime('%Y-%m-%d %H:%M', time.localtime(time.time()))
    filtered_falsepositive = filter_false_positive(df, process_time)
    filtered_winmethodology = filter_win_methodology(filtered_falsepositive, process_time)

    filtered_bashshellshock = filter_bash_shellshock(filtered_winmethodology, process_time)

    filtered_data = filter_webapp_attack(filtered_bashshellshock, process_time)

    all_reports = []
    for alert in filtered_data:
        title = str(alert['displayId']) + ' ' + str(alert['message'].encode('utf-8'))
        content = ""
        for key in alert:
            type_value = type(alert[key])
            if type_value == list or type_value == int or type_value == long or type_value == bool \
                    or type_value == dict or alert[key] is None:
                content += key + ': ' + str(alert[key]).replace('u\'', '\'') + '\n'
            else:
                content += key + ': ' + str(alert[key].encode('ascii', 'ignore')) + '\n'
        created_time = str(alert['createDate'])
        current_report = {'reportTitle': title, 'reportContent': content, 'reportDateTime': created_time}
        all_reports.append(current_report)

    if do_enclave_submissions:
        for staged_report in all_reports:
            start_time = time.time()
            response = ts.submit_report(token, staged_report['reportContent'], staged_report['reportTitle'],
                                        discovered_time_str=staged_report['reportDateTime'],
                                        enclave=True)

            print(response)
            if 'error' in response:
                print("Submission failed with error: {}, {}".format(response['error'], response['message']))
                if response['error'] in ("Internal Server Error", "Access token expired", "Authentication error"):
                    print("Auth token expired, requesting new one")
                    token = ts.get_token()
                else:
                    raise Exception
            else:
                end_time = time.time()
                delta_time = end_time - start_time
                print("Submitted report title {} as TruSTAR IR {}".format(staged_report['reportTitle'],
                                                                          response['reportId']) + " Time:" + str(
                    delta_time))
            if 'reportIndicators' in response and len(response['reportIndicators']) > 0:
                print("Extracted the following indicators: {}".format(json.dumps(response['reportIndicators'])))

            print()
            time.sleep(3)


if __name__ == '__main__':
    main(sys.argv[1])
