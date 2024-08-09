import json
import sys
import threading
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent.telemetry import get_server_stats, send_telemetry, send_scan_telemetry
from openvas_wrapper import OpenVas
import logging

app = FastAPI()

openvas = OpenVas()

default_scan_config_id = "daba56c8-73ec-11df-a475-002264764cea"  # Default to GVMD_FULL_FAST_CONFIG


class StartScanRequest(BaseModel):
    target: str


class ScanTask(BaseModel):
    name: str
    target_id: str


@app.post("/start_scan")
async def start_scan(request: StartScanRequest):
    try:
        task_id = openvas.start_scan(request.target, default_scan_config_id)
        return {"task_id": task_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/wait_task/{task_id}")
async def wait_task(task_id: str):
    try:
        result = openvas.wait_task(task_id)
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# get_scanned_targets_count
@app.get("/get_scanned_targets_count")
async def get_scanned_targets_count():
    try:
        count = openvas.active_scans_count()
        return {"count": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# check_is_vas_online
@app.get("/check_is_vas_online")
async def check_is_vas_online():
    try:
        online = openvas.check_is_vas_online()
        return {"online": online}
    except Exception as e:
        return {"online": False}


@app.get("/get_results")
async def get_results():
    try:
        results = openvas.get_results()
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def telemetry_thread():
    while True:
        # check is macos
        if sys.platform == 'darwin':
            return
        server_stats = get_server_stats()
        json_stats = json.dumps(server_stats, indent=4)
        send_telemetry(json_stats)
        time.sleep(10)  # 30 Sec interval


def send_scan_results():
    while True:
        logging.info("init send_scan_results")
        vas_online = openvas.check_is_vas_online()
        if vas_online:
            send_scan_telemetry()
        logging.info("check_is_vas_online() False")
        time.sleep(15)  # 15 Sec interval


if __name__ == "__main__":
    logging.info("init openvas agent")
    threading.Thread(target=telemetry_thread, daemon=True).start()
    threading.Thread(target=send_scan_results, daemon=True).start()
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8011)
