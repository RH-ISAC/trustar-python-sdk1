from __future__ import print_function

import argparse
import csv
import json

import unicodecsv

from trustar import TruStar

FILE_NAME = 'latest-indicators.csv'

# Default string used to query all indicator types extracted by TruSTAR
DEFAULT_TYPE_STRING = 'ALL'

# Default number of indicators returned
DEFAULT_LIMIT = 5000

# Default interval size
DEFAULT_INTERVAL_SIZE = 24

# All the indicators types extracted by TruSTAR
ALL_TYPES = ['REGISTRY_KEY',
             'SHA1',
             'MD5',
             'URL',
             'IP',
             'EMAIL_ADDRESS',
             'BITCOIN_ADDRESS',
             'MALWARE',
             'SHA256',
             'CVE',
             'SOFTWARE']


def save_to_file(all_data, file_name, source, indicator_types):
    """
    Lists of indicators grouped by type
    :param all_data:
    :param file_name:
    :param source:
    :param indicator_types:
    :return:
    """
    if indicator_types == DEFAULT_TYPE_STRING:
        indicator_types = ALL_TYPES

    with open(file_name, 'wd') as csvfile:
        writer = unicodecsv.writer(csvfile, delimiter=",", quotechar="\"", quoting=csv.QUOTE_MINIMAL)
        for indicator_type in indicator_types:
            if len(all_data[indicator_type]) != 0:
                for data in all_data[indicator_type]:
                    current = data + "," + indicator_type + "," + source
                    writer.writerow(current.split(","))


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=('Query TruSTAR indicators and store them in a CSV file\n'
                                                  'Example:\n\n'
                                                  'python latest_indicators.py -s' +
                                                  ' INCIDENT_REPORT -t "IP,URL" -l 50 -i 12'))
    parser.add_argument('-s', '--source', required=True, dest='source', help='Source can be INCIDENT_REPORT or OSINT')
    parser.add_argument('-t', '--types', required=False, dest='types', help='Types of indicators')
    parser.add_argument('-l', '--limit', required=False, dest='limit',
                        help='Limit on the returned number of indicators')
    parser.add_argument('-i', '--intervalSize', required=False, dest='interval_size',
                        help='Interval size in hours')
    parser.add_argument('-f', '--fileName', required=False, dest='file_name')

    ts = TruStar(config_role="trustar")

    args = parser.parse_args()

    source_type = args.source
    if args.types:
        indicator_types = args.types.split(",")
    else:
        indicator_types = DEFAULT_TYPE_STRING

    if args.limit:
        limit = args.limit
    else:
        limit = DEFAULT_LIMIT

    if args.interval_size:
        interval_size = args.interval_size
    else:
        interval_size = DEFAULT_INTERVAL_SIZE

    if args.file_name:
        file_name = args.file_name
    else:
        file_name = FILE_NAME

    response = ts.query_latest_indicators(ts.get_token(), source_type, indicator_types, limit, interval_size)
    print(json.dumps(response, indent=2))
    save_to_file(response['indicators'], file_name, source_type, indicator_types)


if __name__ == '__main__':
    main()
