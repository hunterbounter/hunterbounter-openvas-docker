import csv
import io
import os

import psutil
import json
import requests
import time
import subprocess
import logging

from datetime import datetime

from agent.openvas_wrapper import OpenVas

default_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"  # Default to GVMD_FULL_FAST_CONFIG

openvas_telemetry = OpenVas()


# Author : HunterBounter

def send_scan_results(scan_results):
    try:
        response = requests.post('https://panel.hunterbounter.com/scan_results/save', data=scan_results)
        if response.status_code != 200:
            print(f"Failed to send scan results: {response.text}")
    except Exception as e:
        print(f"Failed to send scan results: {e}")


def get_host_name():
    try:
        host_name = subprocess.run(['hostname'], capture_output=True, text=True)
        return host_name.stdout.strip()
    except Exception as e:
        return f"Hata: {e}"


get_host_name()


def get_active_interfaces():
    if_addrs = psutil.net_if_addrs()
    active_interfaces = {interface: addrs[0].address for interface, addrs in if_addrs.items() if addrs}
    return active_interfaces


def get_cpu_serial():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    return line.split(':')[1].strip()

    except Exception as e:
        return str(e)


def convert_bytes_to_gb(bytes_value):
    return bytes_value / (1024 * 1024 * 1024)


def classify_status(value, normal_threshold, medium_threshold):
    if value < normal_threshold:
        return "NORMAL"
    elif value < medium_threshold:
        return "MEDIUM"
    else:
        return "CRITICAL"


def get_uptime():
    uptime_seconds = int(time.time() - psutil.boot_time())
    uptime_days = uptime_seconds // (24 * 60 * 60)
    uptime_seconds %= (24 * 60 * 60)
    uptime_hours = uptime_seconds // (60 * 60)
    uptime_seconds %= (60 * 60)
    uptime_minutes = uptime_seconds // 60
    return f"{uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes"


def get_disk_status(used_percent):
    if used_percent < 70:
        return "NORMAL"
    elif used_percent < 90:
        return "MEDIUM"
    else:
        return "CRITICAL"


def get_server_stats():
    try:
        hostname = get_host_name()

        ram_usage = psutil.virtual_memory().percent
        cpu_usage = psutil.cpu_percent()
        active_interfaces = get_active_interfaces()

        total_scan_count = openvas_telemetry.active_scans_count()

        openvas_status = openvas_telemetry.check_is_vas_online()

        if openvas_status:
            openvas_status = "online"
        else:
            openvas_status = "offline"

        # Sistem uptime
        uptime = get_uptime()

        stats = {
            "hostname": hostname,
            "telemetry_type": "openvas",
            "active_scan_count": total_scan_count,
            "openvas_status": openvas_status,
            "active_interfaces": active_interfaces,
            "uptime": uptime,
            "ram_usage": ram_usage,
            "cpu_usage": cpu_usage,
            "active_connections": len(psutil.net_connections()),
            "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        if openvas_status == "online":
            logging.info("Getting targets")
            target_response = get_targets(total_scan_count, 2)

            if target_response['success']:
                logging.info("Targets received")
                logging.info("Response -> " + str(target_response))

                targets = target_response['data']['targets']

                if targets is not None:
                    for target in targets:
                        logging.info(f"Sending scan result for {target}")
                        start_scan_response = openvas_telemetry.start_scan(target, default_scan_config_id)
                        logging.info(f"Start scan response: {start_scan_response}")

        return stats
    except Exception as e:
        print(f"Failed to get server stats: {e}")
        return {"success": False, "message": str(e)}


def get_targets(total_running_scan_count, docker_type):
    url = "https://panel.hunterbounter.com/target"
    headers = {
        "Content-Type": "application/json",
    }
    payload = {
        "total_running_scan_count": total_running_scan_count,
        "docker_type": docker_type
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        logging.info(f"Response: {response.json()}")
        if response.status_code == 200:
            print(f"Success: {response.json()}")
            return response.json()
        else:
            print(f"Failed to get targets: {response.text}")
            return {"success": False, "message": response.text}
    except Exception as e:
        print(f"Failed to get targets: {e}")
        return {"success": False, "message": str(e)}


# Example usage


def send_telemetry(json_stats):
    try:
        response = requests.post('https://panel.hunterbounter.com/telemetry/save', data=json_stats)
        if response.status_code != 200:
            print(f"Failed to send telemetry data: {response.text}")
    except Exception as e:
        print(f"Failed to send telemetry data: {e}")


def send_scan_telemetry():
    try:
        scan_results = openvas_telemetry.get_results()
        print("Scan Results (len): ", len(scan_results))

        # scan results is raise ?
        if scan_results is None or scan_results == {}:
            logging.info("Scan results is None")
            return
            # to json

        # add machineId
        hostname = get_host_name()

        # Add machine ID to each scan result
        for result in scan_results:
            result['machine_id'] = hostname
            result['agent_type'] = "openvas"

        json_result = json.dumps(scan_results, indent=4)

        response = requests.post('https://panel.hunterbounter.com/scan_results/openvas/save', data=json_result,
                                 headers={"Content-Type": "application/json"})
        if response.status_code != 200:
            print(f"Failed to send scan results: {response.text}")
    except Exception as e:
        print(f"Failed to send scan results: {e}")


send_scan_telemetry()
exit(1)
server_stats = get_server_stats()
json_stats = json.dumps(server_stats, indent=4)
send_telemetry(json_stats)
