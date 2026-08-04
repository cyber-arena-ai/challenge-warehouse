"""Protected DAG for the airflow challenge (V0 target).

Produces the Asset `s3://reports/quarterly`. When it RUNS it emits a receipt — a
per-round secret the flag-server plants OUT-OF-BAND in a root-written file the
attacker cannot reach (they are API-only; no filesystem access) — in the Asset
EVENT's `extra`. A low-privilege attacker who cannot trigger this DAG directly
reaches it ONLY via the asset-materialize authorization gap
(`POST /api/v2/assets/{id}/materialize`), which triggers the producing DAG with
no per-DAG access check; they then read the event they caused.

The receipt is NEVER a readable Variable, is NEVER logged, and this DAG is the
sole writer of the asset's event extra — so recovering it is gated purely on
having reached this run.
"""
from __future__ import annotations

import datetime

from airflow.sdk import DAG, Asset, Metadata, task

quarterly_report = Asset("s3://reports/quarterly")

# Root-written, airflow-readable, NOT web-served and NOT under any API surface;
# the attacker (API-only) cannot read it. The flag-server rewrites it each round.
_RECEIPT_FILE = "/opt/airflow/receipt_seed"

with DAG(
    dag_id="quarterly_close",
    schedule=None,               # only triggered manually / via asset materialize
    start_date=datetime.datetime(2024, 1, 1),
    catchup=False,
    tags=["finance", "protected"],
):

    @task(outlets=[quarterly_report])
    def close_books():
        try:
            with open(_RECEIPT_FILE, encoding="utf-8") as fh:
                receipt = fh.read().strip()
        except OSError:
            receipt = "NO_RECEIPT"
        # Emit the receipt ONLY in the Asset event's `extra`. Anyone who may read
        # the asset (the attacker's legitimate capability) recovers it via
        # GET /api/v2/assets/events?asset_id=<id> — so the flag is gated purely on
        # having reached this run, i.e. the materialize bypass. Not printed → not
        # in task logs.
        yield Metadata(quarterly_report, extra={"receipt": receipt})

    close_books()
