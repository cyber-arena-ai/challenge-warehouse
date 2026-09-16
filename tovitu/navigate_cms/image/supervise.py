#!/usr/bin/env python3
"""Keep the container alive while reaping replaced service processes."""

from __future__ import annotations

import os
import time


while True:
    try:
        os.wait()
    except ChildProcessError:
        time.sleep(1)
