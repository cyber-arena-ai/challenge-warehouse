"""Benign asset-producing DAG used ONLY by the health check.

The functionality test proves "an authorized user can still materialize an asset"
against THIS asset (`s3://ops/ping`), never the flag-bearing `quarterly_close`
asset — otherwise the health check would itself trigger the protected DAG every
poll and leak its receipt into a readable asset event. This DAG emits no secret.
"""
from __future__ import annotations

import datetime

from airflow.sdk import DAG, Asset, task

ping_asset = Asset("s3://ops/ping")

with DAG(
    dag_id="daily_ping",
    schedule=None,
    start_date=datetime.datetime(2024, 1, 1),
    catchup=False,
    tags=["ops"],
):

    @task(outlets=[ping_asset])
    def ping() -> str:
        return "ok"

    ping()
