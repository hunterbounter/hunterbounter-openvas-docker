# openvas_wrapper.py
import csv
import datetime
import json
import logging
import base64
import os
import socket
import time
from io import StringIO
from typing import Union, List, Dict, Any

import gvm
from gvm.protocols import gmp as openvas_gmp
from gvm import transforms

ALL_IANA_ASSIGNED_TCP_UDP = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
GVMD_FULL_FAST_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
GVMD_FULL_DEEP_ULTIMATE_CONFIG = "74db13d6-7489-11df-91b9-002264764cea"
OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
GMP_USERNAME = "admin"
GMP_PASSWORD = "admin"
WAIT_TIME = 30
hostname = "localhost"
IS_UPDATE_VT = False

LOG_FILE = "/usr/local/var/log/gvm/gvmd.log"
VT_CHECK = b"Updating VTs in database ... done"

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()
                    ])

logger = logging.getLogger(__name__)


class OpenVas:
    """OpenVas wrapper to enable using openvas scanner from ostorlab agent class."""

    def start_scan(self, target: str, scan_config_id: str) -> str:
        """Start OpenVas scan on the ip provided.

        Args:
            target: Target IP or Domain to scan.
            scan_config_id: scan configuration used by the task.
        Returns:
            OpenVas task identifier.
        """
        connection = gvm.connections.TLSConnection(hostname=hostname)
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            logger.debug("Creating target")
            target_id = self._create_target(gmp, target, ALL_IANA_ASSIGNED_TCP_UDP)
            logger.debug("Creating task for target %s", target_id)
            logger.info("Config ID is %s", str(scan_config_id))
            task_id = self._create_task(
                gmp,
                target,
                target_id,
                GVMD_FULL_FAST_CONFIG,
                OPENVAS_SCANNER_ID,
            )
            logger.debug("Creating report for task %s", task_id)
            report_id = self._start_task(gmp, task_id)
            logger.info(
                "Started scan of host %s. Corresponding report ID is %s",
                str(target),
                str(report_id),
            )
            return task_id

    def _create_target(
            self, gmp: openvas_gmp.Gmp, target: str, port_list_id: str
    ) -> str:
        name = f"Testing Host {target} {datetime.datetime.now()}"
        response = gmp.create_target(
            name=name, hosts=[target], port_list_id=port_list_id
        )
        return response.get("id")

    def _create_task(
            self,
            gmp: openvas_gmp.Gmp,
            ip: str,
            target_id: str,
            scan_config_id: str,
            scanner_id: str,
    ) -> str:
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_create_task.

        Args:
            gmp: GMP object.
            ip: Target ip to scan.
            target_id: Ids of hosts targeted by the scan.
            scan_config_id: scan configuration used by the task
            scanner_id: scanner to use for scanning the target.

        Returns:
            - OpenVas task identifier.
        """
        name = f"Scan Host {ip}"
        response = gmp.create_task(
            name=name,
            config_id=scan_config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        return response.get("id")

    def _start_task(self, gmp: openvas_gmp.Gmp, task_id: str) -> str:
        """Create gmp task https://docs.greenbone.net/API/GMP/gmp-21.04.html#command_start_task.

        Args:
            gmp: GMP object.
            task_id: task id.

        Returns:
            - task result.
        """
        response = gmp.start_task(task_id)
        return response[0].text

    def check_is_vas_online(self):
        """Check if openvas is online.

        Returns:
            - bool: True if openvas is online, False otherwise.
        """
        print("check_is_vas_online")
        global IS_UPDATE_VT
        print("IS_UPDATE_VT -> ", IS_UPDATE_VT)
        if not IS_UPDATE_VT:
            try:
                if not os.path.exists(LOG_FILE):
                    logger.info("Log file does not exist: %s", LOG_FILE)
                    return False

                with open(LOG_FILE, "rb") as f:
                    for line in f.readlines():
                        if VT_CHECK in line:
                            IS_UPDATE_VT = True
                            return True
                    logger.info("VTs are not updated yet")
                    return False
            except Exception as e:
                logger.info("Failed to read log file: %s", str(e))
                return False

        try:
            connection = gvm.connections.TLSConnection(hostname="localhost")
            transform = transforms.EtreeTransform()
            with openvas_gmp.Gmp(connection, transform=transform) as gmp:
                try:
                    gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
                    return True
                except Exception as e:
                    logger.info("Failed to connect to OpenVas: %s", str(e))
                    return False
        except Exception as e:
            logger.info("Failed to connect to OpenVas: %s", str(e))
            return False

    def wait_task(self, task_id: str) -> bool:
        """check gmp task status and wait until it is Done.

        Args:
            task_id: task id.

        Returns:
            - bool task status.
        """
        logger.info("Waiting for task %s", task_id)
        connection = gvm.connections.TLSConnection(hostname=hostname)
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            while True:
                try:
                    resp_tasks = gmp.get_tasks().xpath("task")
                    for task in resp_tasks:
                        logger.debug("Checking task %s", task.xpath("@id")[0])
                        if task.xpath("@id")[0] == task_id:
                            logger.info(
                                "Scan progress %s", str(task.find("progress").text)
                            )
                            if task.find("status").text == "Done":
                                return True
                except socket.timeout:
                    logger.info("Socket timeout error")
                time.sleep(WAIT_TIME)

    def active_scans_count(self) -> int:
        """Fetch the number of currently scanned targets.

        Returns:
            - int: The number of targets currently being scanned.
        """
        try:
            connection = gvm.connections.TLSConnection(hostname=hostname)
            transform = transforms.EtreeTransform()
            with openvas_gmp.Gmp(connection, transform=transform) as gmp:
                gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
                resp_tasks = gmp.get_tasks().xpath("task")
                scanned_targets_count = sum(1 for task in resp_tasks if task.find("status").text != "Done")
                return scanned_targets_count
        except Exception as e:
            logger.info("Failed to get active scans count: %s", str(e))
            return 0

    def get_report(self, report_id, file_name):
        # First, find the right report ID
        connection = gvm.connections.TLSConnection(hostname=hostname)
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            resp = gmp.get_report_formats()
            report_formats = resp.xpath("//report_format")  # [-1].xpath("@id")
            report_format_id = False
            extension = ""
            for f in report_formats:
                save_file = False
                if f.xpath(".//name")[1].text == "CSV Results":
                    report_format_id = f.xpath("@id")[0]
                    save_file = True
                    extension = "csv"
                elif f.xpath(".//name")[1].text == "XML":
                    report_format_id = f.xpath("@id")[0]
                    save_file = True
                    extension = "xml"

                # Print the data and/or add it to a file
                resp = gmp.get_report(report_id, report_format_id=report_format_id, ignore_pagination=True)

                if save_file == True:
                    if extension == "csv":
                        f = open("{}.{}".format(file_name, extension), "wb")
                        csv_in_b64 = resp.xpath('report/text()')[0]
                        csv = base64.b64decode(csv_in_b64)
                        f.write(csv)
                        f.close()
                        print("Report saved to {}.{}".format(file_name, extension))
                    if extension == "xml":
                        f = open("{}.{}".format(file_name, extension), "w")
                        resp = gmp.get_report(report_id, report_format_id=report_format_id, ignore_pagination=True)
                        print("xml resp")
                        # data = print_pretty_xml(resp)
                        # f.write(data)
                        # f.close()

    def get_results(self) -> Union[str, list[dict[Any, Any]]]:
        """get gmp report result in json format with detailed keys.

        Returns:
            - Union[str, list[dict[Any, Any]]]: JSON formatted
        """
        connection = gvm.connections.TLSConnection(hostname=hostname)
        transform = transforms.EtreeTransform()
        with openvas_gmp.Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            report_format_id = ""

            report_formats_response = gmp.get_report_formats()
            report_formats = report_formats_response.xpath('report_format')
            print("Report Formats Response -> ", report_formats_response)
            for report_format in report_formats:
                print("Report Format -> ", report_format.find('name').text)
                if report_format.find('name').text.startswith("CSV Results"):
                    report_format_id = report_format.attrib.get("id")

            if not report_format_id:
                print("CSV report format not found")
                return ""

            print("Report Format Id -> ", report_format_id)

            result_reports = []
            try:
                all_reports_response = gmp.get_reports()
                all_reports = all_reports_response.xpath('report')
                print("All Reports Response -> ", all_reports_response)
                for report in all_reports:
                    print("Report -> ", report.tag)
                    result_reports.append(report.attrib.get("id"))

                print("result_reports -> ", result_reports)

                if not result_reports:
                    print("No reports found")
                    return ""

                json_results = []
                for report_id in result_reports:
                    print("Report ID -> ", report_id)
                    print("Get Report Another Func")
                    self.get_report(report_id, "report")
                    response = gmp.get_report(
                        report_id,
                        report_format_id=report_format_id,
                        # ignore_pagination=True,
                        details=True,
                        filter_string="apply_overrides=0 levels=hml rows=100 min_qod=70 first=1 sort-reverse=severity",
                    )
                    print("Get Report Response -> ", response)
                    report_element = response.find("report")
                    if (
                            report_element is not None
                            and report_element.find("report_format") is not None
                    ):
                        content = report_element.find("report_format").tail
                        data = str(base64.b64decode(content), "utf-8")

                        csv_reader = csv.DictReader(StringIO(data))
                        for row in csv_reader:

                            trimmed_row = {k: v.strip() for k, v in row.items() if v and v.strip()}
                            if trimmed_row:  # Boş olmayan verileri ekle
                                trimmed_row['report_id'] = report_id
                                json_results.append(trimmed_row)

                # json_output = json.dumps(json_results, indent=4)
                # print(json_output)
                return json_results
            except Exception as e:
                print(e)
                return ""
