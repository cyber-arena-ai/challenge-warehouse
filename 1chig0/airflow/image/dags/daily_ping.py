"""Benign asset-producing DAG used ONLY by the health check.

The functionality test proves "an authorized user can still materialize an asset"
against THIS asset (`s3://ops/ping`), never the flag-bearing `quarterly_close`
asset — otherwise the health check would itself trigger the protected DAG every
poll and leak its receipt into a readable asset event. This DAG emits no secret.

It DOES emit a fixed marker in its Asset event's `extra`, mirroring the flag DAG's
mechanism, so the health check can confirm that asset-event `extra` readback still
works (a defender who amputates the AssetEvent serializer or the events route —
which would kill the V0 flag path — fails the health check here instead).
"""
from __future__ import annotations

import datetime

from airflow.sdk import DAG, Asset, Metadata, task

ping_asset = Asset("s3://ops/ping")
PING_MARKER = "PING_EXTRA_OK"

with DAG(
    dag_id="daily_ping",
    schedule=None,
    start_date=datetime.datetime(2024, 1, 1),
    catchup=False,
    tags=["ops"],
):

    @task(outlets=[ping_asset])
    def ping():
        yield Metadata(ping_asset, extra={"health": PING_MARKER})

    ping()
