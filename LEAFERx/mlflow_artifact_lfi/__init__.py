"""mlflow-lfi — MLflow 2.1.1 artifact-download LFI (CVE-2023-1177).

Real-world challenge built from `mlflow/mlflow` pinned at v2.1.1. The
tracking server validates the artifact `?path=` param but NOT the
artifact ROOT it joins onto — and that root is attacker-controlled (a
model version's `source`, or an experiment's `artifact_location`). So an
unauthenticated client can point the root at any local directory and make
the server read an arbitrary file with its own filesystem permission —
the textbook confused-deputy boundary.

  Flag      : /opt/secret/flag.txt, owned by the `mlflow` runtime user,
              mode 600. No legitimate endpoint serves it.
  Attack    : create a model version with source="file://%00/opt/secret/",
              then GET /model-versions/get-artifact?path=flag.txt (or the
              equivalent run-artifact / artifact_location vector).
  Defense   : edit /srv/challenge/mlflow/server/handlers.py to validate the
              artifact root (reject non-proxied local roots; legit ones are
              mlflow-artifacts:/), then restart_service. The CHECKER does a
              legitimate proxied artifact round-trip, so amputating the
              endpoint fails it.
"""

from .challenge import MlflowLfiChallenge

__all__ = ["MlflowLfiChallenge"]
