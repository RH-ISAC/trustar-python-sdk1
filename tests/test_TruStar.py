import unittest

from trustar import *

import time
import json


DAY = 24 * 60 * 60 * 1000

current_time = int(time.time()) * 1000
yesterday_time = current_time - DAY
old_time = current_time - DAY * 365 * 3


class TruStarTests(unittest.TestCase):

    def setUp(self):
        self.ts = TruStar()

    def test_get_reports(self):
        for t in [yesterday_time, old_time]:
            reports = self.ts.get_reports(from_time=t,
                                          to_time=current_time,
                                          distribution_type=DISTRIBUTION_TYPE_COMMUNITY)
            print(reports)

    def test_submit_report(self):
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
        self.assertEqual(result[u'reportBody'], report.body)

        # add tag
        result = self.ts.add_enclave_tag(report_id=report.id,
                                         enclave_id=self.ts.enclave_ids[0],
                                         name="some_tag")

        # get tags
        result = self.ts.get_enclave_tags(report_id=report.id)
        print(json.dumps(result, indent=4))

        result = self.ts.delete_enclave_tag(report_id=report.id,
                                            enclave_id=self.ts.enclave_ids[0],
                                            name="some_tag")
        self.assertEqual(result, "OK")

        # delete report
        response = self.ts.delete_report(report_id=report.id)
        self.assertEqual(response.status_code, 200)


    def test_community_trends(self):
        for indicator_type in ['malware', 'cve', None]:
            result = self.ts.get_community_trends(indicator_type=indicator_type)

    def test_get_related_indicators(self):
        result = self.ts.get_related_indicators(indicators=["evil", "1.2.3.4", "wannacry"],
                                                sources=["osint", "incident_report"])
        # print(json.dumps(result, indent=4))

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
