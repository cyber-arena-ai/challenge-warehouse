#!/usr/bin/env python3
"""Create the datastore if needed and restore the published API credential."""

from __future__ import annotations

import base64
import hashlib
import secrets
import sys
from pathlib import Path

SOURCE = Path("/srv/challenge/changedetection")
DATASTORE = "/srv/changedetection/datastore"
API_TOKEN = "changedetection-operator-api-token-v1"

sys.path.insert(0, str(SOURCE))

from changedetectionio.store import ChangeDetectionStore  # noqa: E402


def main() -> None:
    store = ChangeDetectionStore(
        datastore_path=DATASTORE,
        include_default_watches=False,
        version_tag="1d7d812",
    )
    application = store.data["settings"]["application"]
    application["api_access_token"] = API_TOKEN
    application["api_access_token_enabled"] = True
    if not application.get("password"):
        # Lock the browser UI with a per-box credential that is never published;
        # the operator API token remains the intended authenticated interface.
        salt = secrets.token_bytes(32)
        password = secrets.token_bytes(32)
        key = hashlib.pbkdf2_hmac("sha256", password, salt, 100_000)
        application["password"] = base64.b64encode(salt + key).decode()
    store.commit()


if __name__ == "__main__":
    main()
