from trustar import TruStar, Report, get_logger
import sys
import csv


logger = get_logger(__name__)

# mapping of CSV column names to report fields
MAPPING = {
    "title": "name",
    "body": "content",
    "external_id": "id"
}


def main(csv_path):
    """
    Reads reports from a CSV and submits them to TruSTAR.

    :param csv_path: The path to the CSV
    """

    # initialize SDK
    ts = TruStar()

    # read in CSV
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)

        # iterate over rows
        for row in reader:

            # define method to get report field from CSV row
            def get_field(field):
                return row.get(MAPPING.get(field))

            # construct report from CSV row
            report = Report(title=get_field('title'),
                            body=get_field('body'),
                            external_id=get_field('external_id'),
                            is_enclave=True,
                            enclave_ids=ts.enclave_ids)

            # submit report
            ts.submit_report(report)

            logger.info("Submitted report: %s" % report)


if __name__ == '__main__':

    # ensure csv path was passed as argument
    if len(sys.argv) < 2:
        raise Exception("Program requires one argument, the path to the CSV.")

    # call main function
    main(sys.argv[1])
