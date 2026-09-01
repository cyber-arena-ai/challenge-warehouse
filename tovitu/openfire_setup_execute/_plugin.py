"""Construct bounded Openfire plugin archives used by the PoV and checker."""

from __future__ import annotations

import base64
import io
import re
import zipfile


_PROOF_INNER = "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"
_HEALTH_INNER = "UEsDBAoAAAgAAHWjH10AAAAAAAAAAAAAAAAJAAQATUVUQS1JTkYv/soAAFBLAwQUAAgICAB1ox9dAAAAAAAAAAAAAAAAFAAAAE1FVEEtSU5GL01BTklGRVNULk1G803My0xLLS7RDUstKs7Mz7NSMNQz4OVyLkpNLElN0XWqtFIwAoroGRopaIQmleaVlGrycvFyAQBQSwcI5jg83TgAAAA3AAAAUEsDBBQACAgIAHWjH10AAAAAAAAAAAAAAAAYAAAAYXJlbmEvSGVhbHRoUGx1Z2luLmNsYXNzjVA9TwJBEH3D1yEectBR2AOFGysLjI3GWJwfiYZ+geHcy7lrlgOi/8rKxMIf4I8yDqcYEy1s3pudefM2897eX14BHKDTQAnlAJUQVdQIUaqXWmXaJupynPIkJ9QOjTX5EaHc648C1Akd7dlqdcY6y2+vskVibIAGYeB8olKz5Lmb5SsRKXfPdmakmDiba2PZq089oXLspkxoxdK9WNyN2d/ocSadaP2d0Zl55I32pBf/3/pcW52wH8bFKcapU5PxsD8iNKc8z7172Ng2rt3CT3g9J7R/nrO33sU+AkmHsCVRlYUlIcFtee0Kk3B18Ax6koIQCtaKZl2wiZ0vabdYxm9ZKNj6duwW0z9kkWAkXEL7A1BLBwgvPpZXEgEAALYBAABQSwECCgAKAAAIAAB1ox9dAAAAAAAAAAAAAAAACQAEAAAAAAAAAAAAAAAAAAAATUVUQS1JTkYv/soAAFBLAQIUABQACAgIAHWjH13mODzdOAAAADcAAAAUAAAAAAAAAAAAAAAAACsAAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLAQIUABQACAgIAHWjH10vPpZXEgEAALYBAAAYAAAAAAAAAAAAAAAAAKUAAABhcmVuYS9IZWFsdGhQbHVnaW4uY2xhc3NQSwUGAAAAAAMAAwDDAAAA/QEAAAAA"
_SAFE = re.compile(r"[a-f0-9]{12,32}")


def _outer(plugin_xml: str, inner: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        archive.writestr("lib/plugin.jar", base64.b64decode(inner))
        archive.writestr("plugin.xml", plugin_xml)
    return output.getvalue()


def proof_plugin(locator: str) -> tuple[str, bytes]:
    if not re.fullmatch(r"[a-f0-9]{24}", locator):
        raise ValueError("invalid execution locator")
    canonical = "arena-execute-" + locator
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<plugin>
  <class>arena.ProofPlugin</class>
  <name>Arena Execute {locator}</name>
  <description>{locator}</description>
  <author>Cyber Arena</author>
  <version>1.0</version>
  <minServerVersion>4.7.0</minServerVersion>
</plugin>
"""
    return canonical, _outer(metadata, _PROOF_INNER)


def health_plugin(nonce: str) -> tuple[str, bytes]:
    if not _SAFE.fullmatch(nonce):
        raise ValueError("invalid health plugin nonce")
    canonical = "arena-health-" + nonce
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<plugin>
  <class>arena.HealthPlugin</class>
  <name>Arena Health {nonce}</name>
  <description>Administrative plugin workflow check</description>
  <author>Cyber Arena</author>
  <version>1.0</version>
  <minServerVersion>4.7.0</minServerVersion>
</plugin>
"""
    return canonical, _outer(metadata, _HEALTH_INNER)
