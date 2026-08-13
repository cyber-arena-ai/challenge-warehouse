# Stale checker artifacts

`image_checker.py` and `image_checker.sh` are the retired in-container checker.
They are retained only as migration history. The live image contains a minimal
fixture provisioner at `/arena/checker.py`; the authoritative behavior check is
the repository-level `checker.py` executed by the external health poller.
