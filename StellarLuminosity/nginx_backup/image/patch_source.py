#!/usr/bin/env python3
"""Apply the challenge-local proof-safe backup ordering adaptation."""

from pathlib import Path
import sys


source_root = Path(sys.argv[1])
backup_source = source_root / "internal" / "backup" / "backup.go"
old = "createZipArchiveToBuffer(&buffer, tempDir)"
new = "createOrderedBackupArchiveToBuffer(&buffer, tempDir)"
content = backup_source.read_text(encoding="utf-8")
if content.count(old) != 1:
    raise SystemExit("unexpected upstream backup implementation")
backup_source.write_text(content.replace(old, new), encoding="utf-8")
