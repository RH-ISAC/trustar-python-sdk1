import unittest
from trustar import *

import time
import json
import yaml
import random


DAY = 24 * 60 * 60 * 1000

current_time = int(time.time()) * 1000
yesterday_time = current_time - DAY
old_time = current_time - DAY * 365 * 3

INDICATOR_TYPES = [
    'IP',
    'CIDR_BLOCK',
    'URL',
    'EMAIL_ADDRESS',
    'MD5',
    'SHA1',
    'SHA256',
    'MALWARE',
    'SOFTWARE',
    'REGISTRY_KEY',
    'CVE',
    'BITCOIN_ADDRESS',
    'DOMAIN',
    'FQDN',
    'PERSON',
    'LOCATION',
    'ORGANIZATION',
    'DATE',
]


def generate_ip(start_range=100):
    return ".".join(map(str, (random.randint(start_range, 255) for _ in range(4))))


class TruStarTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        with open('config.yml', 'r') as f:
            config = yaml.load(f)

        cls.ts = TruStar(config=config['trustar']['dev'])

    def test_get_reports(self):
        """
        Test that we can get all reports fitting some filters.
        """

        for from_time in [yesterday_time, old_time]:
            reports = self.ts.get_reports(from_time=from_time,
                                          to_time=current_time,
                                          distribution_type=DISTRIBUTION_TYPE_COMMUNITY)
            print(reports)

    def test_submit_report(self):
        """
        Test the entire workflow of submitting, updating, getting, and deleting a report.
        """
        # create and submit report
        report = Report(title="Report 1",
                        body="Blah blah blah",
                        time_began=yesterday_time,
                        enclave_ids=self.ts.enclave_ids)
        result = self.ts.submit_report(report=report)
        report.id = result['reportId']

        # update report
        report.body = "Bleh bleh bleh"
        self.ts.update_report(report=report)

        # get report
        result = self.ts.get_report_details(report_id=report.id)
        self.assertEqual(result['reportBody'], report.body)

        # add tag
        result = self.ts.add_enclave_tag(report_id=report.id,
                                         enclave_id=self.ts.enclave_ids[0],
                                         name="some_tag")

        # get tags
        result = self.ts.get_enclave_tags(report_id=report.id)
        print(json.dumps(result, indent=4))

        # delete tag
        result = self.ts.delete_enclave_tag(report_id=report.id,
                                            enclave_id=self.ts.enclave_ids[0],
                                            name="some_tag")
        self.assertEqual(result, "OK")


        # delete report
        response = self.ts.delete_report(report_id=report.id)
        self.assertEqual(response.status_code, 200)

    def test_community_trends(self):
        """
        Check that we can get community trending indicators, and that the total
        number of each indicator type (except MALWARE and CVE) is consistent with
        the total number returned when we get ALL indicator types (except MALWARE and CVE).
        """
        totals = []
        for indicator_type in INDICATOR_TYPES + [None]:
            result = self.ts.get_community_trends(indicator_type=indicator_type)
            print(result)

            if indicator_type is not None:
                if indicator_type not in ['CVE', 'MALWARE']:
                    totals.append(result.total_elements)
                for item in result:
                    self.assertEqual(item['indicatorType'], indicator_type)

            else:
                self.assertEqual(sum(totals), result.total_elements)

            correlation_counts = [item['correlationCount'] for item in result]
            for i in range(len(correlation_counts) - 1):
                self.assertTrue(correlation_counts[i] > correlation_counts[i+1])


    def test_get_related_indicators_and_correlated_reports(self):
        """
        Submits a group of reports that contain common indicators, then checks that
        getting related indicators and correlated reports returns the expected results.
        """

        #########
        # SETUP #
        #########

        indicators = [
            "www.wefrrtdgwefwef1234.org",
            "wefoijseroijr@yahoo.org"
        ]

        related = ["www.abcxyz1235.com"] + [generate_ip() for _ in range(27)]

        indicator_groups = [
            related[:5],
            related[5:9],
            related[9:19],
            related[19:25],
            related[25:]
        ]

        reports = []

        count = 0
        for group in indicator_groups:
            count += 1
            report = Report(
                title="Test_Get_Related_Indicators_Report_%s" % count,
                body=" some words ".join([indicators[count % 2]] + group),
                enclave_ids=self.ts.enclave_ids
            )
            result = self.ts.submit_report(report=report)
            report.id = result['reportId']
            reports.append(report)

        ###############
        # GET RELATED #
        ###############

        server_related = list(self.ts.get_related_indicators_iterator(indicators=indicators, sources=["incident_report"]))
        related_reports = self.ts.get_correlated_reports(indicators=indicators)

        ###########
        # CLEANUP #
        ###########

        for report in reports:
            self.ts.delete_report(report_id=report.id)

        ##########
        # ASSERT #
        ##########

        server_indicator_values = set([ind['value'].lower() for ind in server_related])
        for indicator in related:
            self.assertTrue(indicator.lower() in server_indicator_values)

        for report in reports:
            self.assertTrue(report.id in related_reports)

    def test_get_related_indicators(self):
        result = self.ts.get_related_indicators(indicators=["evil", "1.2.3.4", "wannacry"],
                                                sources=["osint", "incident_report"])
        print(result)

    def test_get_external_related_indicators(self):
        result = self.ts.get_related_external_indicators(indicators=["evil", "1.2.3.4", "wannacry"],
                                                         sources=["facebook", "crowdstrike"])

    def test_get_correlated_reports(self):
        result = self.ts.get_correlated_reports(["evil", "wannacry"])

    def test_page_iterator(self):
        def func(page_size, page_number):
            return self.ts.get_reports(from_time=old_time,
                                       to_time=current_time,
                                       distribution_type=DISTRIBUTION_TYPE_COMMUNITY,
                                       page_number=page_number,
                                       page_size=page_size)

        page_iterator = self.ts.get_page_generator(func)

        count = 0
        total = None
        for page in page_iterator:

            if total is not None:
                self.assertEqual(total, page.total_elements)
            else:
                total = page.total_elements

            count += len(page.items)

        self.assertEqual(total, count)

    def test_iterator(self):
        def func(page_size, page_number):
            return self.ts.get_reports(from_time=old_time,
                                       to_time=current_time,
                                       distribution_type=DISTRIBUTION_TYPE_COMMUNITY,
                                       page_number=page_number,
                                       page_size=page_size)

        iterator = self.ts.get_generator(func)

        count = 0
        total = func(page_number=0, page_size=1).total_elements
        for report in iterator:
            count += 1

        self.assertEqual(count, total)

    def test_report_iterator(self):
        reports = self.ts.get_report_iterator(from_time=old_time,
                                              to_time=current_time,
                                              distribution_type=DISTRIBUTION_TYPE_COMMUNITY)
        count = 0
        total = self.ts.get_reports(from_time=old_time,
                                    to_time=current_time,
                                    distribution_type=DISTRIBUTION_TYPE_COMMUNITY,
                                    page_number=0,
                                    page_size=1).total_elements

        for report in reports:
            count += 1
            print(report)

        self.assertEqual(count, total)


if __name__ == '__main__':
    unittest.main()
