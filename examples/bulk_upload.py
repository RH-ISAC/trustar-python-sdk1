#!/usr/bin/env python

"""
Submit one or more reports from local files (txt, pdf)

Requirements
pip install trustar, pdfminer

Run
python bulk_upload.py --dir ./files_to_upload_dir/ --ts_conf ./trustar_api.conf
"""
from __future__ import print_function

import argparse
import os
import time
import logging
import pdfminer.pdfinterp
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from cStringIO import StringIO
from trustar import TruStar

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def extract_pdf(file_name):
    """
    Extract text from a pdf file
    :param file_name path to pdf to read
    :return text from pdf
    """

    rsrcmgr = pdfminer.pdfinterp.PDFResourceManager()
    sio = StringIO()
    laparams = LAParams()
    device = TextConverter(rsrcmgr, sio, codec='utf-8', laparams=laparams)
    interpreter = pdfminer.pdfinterp.PDFPageInterpreter(rsrcmgr, device)

    # Extract text from pdf file
    fp = file(file_name, 'rb')
    for page in PDFPage.get_pages(fp, maxpages=20):
        interpreter.process_page(page)
    fp.close()

    text = sio.getvalue()

    # Cleanup
    device.close()
    sio.close()

    return text


def process_file(source_file):
    """
    Extract text from a file (pdf, txt, eml, csv, json)
    :param source_file path to file to read
    :return text from file
    """
    if source_file.endswith(('.pdf', '.PDF')):
        txt = extract_pdf(source_file)
    elif source_file.endswith(('.txt', '.eml', '.csv', '.json')):
        f = open(source_file, 'r')
        txt = f.read()
    else:
        logger.info("Unsupported file extension for file {}"
                .format(source_file))
        return ""
    return txt


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=(
                                         'Submit one or more reports from local files (txt, pdf, docx, etc) '
                                         'in a directory\n\n'
                                         'Example:\n'
                                         'python bulk_upload.py --dir ./sample_reports --ts_conf ./trustar.conf'))
    parser.add_argument('--dir', '-d', help='Path containing report files', required=True)
    parser.add_argument('--ts_config', '-c', help='Path containing trustar api config', required=True)
    parser.add_argument('-i', '--ignore', dest='ignore', action='store_true',
                        help='Ignore history and resubmit already procesed files')

    args = parser.parse_args()
    source_report_dir = args.dir

    ts_config = args.ts_config
    ts = TruStar(config_file=ts_config, config_role="trustar")

    # process all files in directory
    logger.info("Processing and submitting each source file in %s as a TruSTAR Incident Report" % source_report_dir)

    processed_files = set()

    processed_files_file = os.path.join(source_report_dir, "processed_files.log")
    if os.path.isfile(processed_files_file) and not args.ignore:
        processed_files = set(line.strip() for line in open(processed_files_file))

    skipped_files_file = os.path.join(source_report_dir, "skipped_files.log")

    with open(processed_files_file, 'a', 0) as pf:
        for (dirpath, dirnames, filenames) in os.walk(source_report_dir):
            for source_file in filenames:

                if (source_file == "processed_files.log" or
                    source_file == "skipped_files.log"):
                    continue

                if source_file in processed_files:
                    logger.debug("File {} was already processed. Ignoring."
                                 .format(source_file))
                    continue

                logger.info("Processing source file %s " % source_file)
                try:
                    path = os.path.join(source_report_dir, source_file)
                    report_body = process_file(path)
                    if not report_body:
                        logger.debug("File {} ignored for no data".format(source_file))
                        raise

                    # response_json = ts.submit_report(token, report_body, "COMMUNITY: " + file)
                    token = ts.get_token()
                    logger.info("Report {}".format(report_body))
                    try:
                        response_json = ts.submit_report(token, report_body, 
                                "ENCLAVE: " + source_file, enclave=True)
                    except Exception as e:
                        if '413' in e.message:
                            logger.warn("Could not submit file {}. Contains more indicators than currently supported."
                                        .format(source_file))
                        else:
                            raise

                    report_id = response_json['reportId']
                    logger.info("SUCCESSFULLY SUBMITTED REPORT, TRUSTAR REPORT as Incident Report ID %s" % report_id)
                    pf.write("%s\n" % source_file)

                    # if 'reportIndicators' in response_json:
                    #     print("Extracted the following indicators: {}".format(response_json['reportIndicators']))
                    # else:
                    #     print("No indicators returned from  report id {0}".format(report_id))
                    #
                    # # if 'correlatedIndicators' in response_json:
                    #     print(
                    #         "Extracted the following correlated indicators: {}".format(
                    #             response_json['correlatedIndicators']))
                    # else:
                    #     print("No correlatedIndicators found in report id {0}".format(report_id))

                except Exception as e:
                    logger.error("Problem with file %s, exception: %s " % (source_file, e))
                    with open(skipped_files_file, 'w', 0) as sf:
                        sf.write("{}\n".format(source_file))
                    continue

                time.sleep(2)


if __name__ == '__main__':
    main()
