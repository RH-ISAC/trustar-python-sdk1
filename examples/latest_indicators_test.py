from __future__ import print_function
import requests
import json
import unicodecsv
import csv

from trustar import TruStar

FILE_NAME = 'indicators-api-test.csv'


def save_to_file(all_data, file_name, indicator_types):
    """
    Lists of indicators grouped by type
    :param all_data:
    :param file_name:
    :param indicator_types:
    :return:
    """
    with open(file_name, 'wd') as csvfile:
        writer = unicodecsv.writer(csvfile, delimiter=",", quotechar="\"", quoting=csv.QUOTE_MINIMAL)
        for indicator_type in indicator_types:
            if len(all_data[indicator_type]) != 0:
                writer.writerow(all_data[indicator_type])


def query_latest_indicators(self,
                            access_token,
                            source,
                            indicator_types,
                            limit,
                            interval_size):
    """
    Finds all latest indicators
    :param interval_size:
    :param source:
    :param self:
    :param access_token:
    :param limit:
    :param indicator_types:
    """

    headers = {"Authorization": "Bearer " + access_token}
    payload = {'source': source, 'types': indicator_types, 'limit': limit, 'intervalSize': interval_size}
    resp = requests.get(self.base + "indicators/latest", payload, headers=headers, verify=False)
    return json.loads(resp.content)


def main():

    ts = TruStar(config_file="trustar_int.conf", config_role="trustar")

    source_type = 'INCIDENT_REPORT'
    indicator_types = ['IP', 'URL', 'EMAIL_ADDRESS']
    limit = 5000
    interval_size = 2

    response = query_latest_indicators(ts, ts.get_token(), source_type, indicator_types, limit, interval_size)
    print(response)
    save_to_file(response['indicators'], FILE_NAME, indicator_types)


if __name__ == '__main__':
    main()
