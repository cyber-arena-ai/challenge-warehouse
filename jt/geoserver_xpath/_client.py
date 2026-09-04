"""Small stdlib GeoServer WFS/WMS client shared by probes and the PoV."""

from __future__ import annotations

import base64
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape

TIMEOUT = 20


def resolve_host(host: str) -> str:
    # Docker service aliases contain underscores (for example ``team1_prod``),
    # which Tomcat rejects in the HTTP Host header. Connect to the alias's
    # network address so urllib emits a standards-compliant numeric Host.
    if "_" in host:
        try:
            host = socket.gethostbyname(host)
        except socket.gaierror:
            pass
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


class GeoServerClient:
    def __init__(
        self,
        base: str,
        username: str = "",
        password: str = "",
        *,
        timeout: int = TIMEOUT,
    ) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.authorization = ""
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.authorization = "Basic " + token

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        *,
        content_type: str = "",
    ) -> tuple[int, bytes, dict[str, str]]:
        headers = {"Accept": "*/*"}
        if self.authorization:
            headers["Authorization"] = self.authorization
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(
            self.base + path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read(2_000_000), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read(2_000_000), dict(error.headers)

    @staticmethod
    def _query(params: dict[str, object]) -> str:
        return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

    def capabilities(self) -> tuple[int, bytes]:
        query = self._query({
            "service": "WFS",
            "version": "2.0.0",
            "request": "GetCapabilities",
        })
        status, body, _ = self.request("GET", "/geoserver/wfs?" + query)
        return status, body

    def feature(
        self,
        type_name: str,
        *,
        resource_id: str = "",
        cql_filter: str = "",
        count: int = 1,
    ) -> tuple[int, object]:
        params: dict[str, object] = {
            "service": "WFS",
            "version": "2.0.0",
            "request": "GetFeature",
            "typeNames": type_name,
            "outputFormat": "application/json",
            "count": count,
        }
        if resource_id:
            params["resourceId"] = resource_id
        if cql_filter:
            params["CQL_FILTER"] = cql_filter
        status, body, _ = self.request(
            "GET", "/geoserver/wfs?" + self._query(params)
        )
        try:
            return status, json.loads(body)
        except ValueError:
            return status, body.decode(errors="replace")

    def property_values(
        self, type_name: str, property_name: str, *, count: int = 2
    ) -> tuple[int, bytes]:
        query = self._query({
            "service": "WFS",
            "version": "2.0.0",
            "request": "GetPropertyValue",
            "typeNames": type_name,
            "valueReference": property_name,
            "count": count,
        })
        status, body, _ = self.request("GET", "/geoserver/wfs?" + query)
        return status, body

    def map_png(self) -> tuple[int, bytes]:
        query = self._query({
            "service": "WMS",
            "version": "1.1.1",
            "request": "GetMap",
            "layers": "topp:states",
            "styles": "",
            "srs": "EPSG:4326",
            "bbox": "-180,-90,180,90",
            "width": 64,
            "height": 32,
            "format": "image/png",
        })
        status, body, _ = self.request("GET", "/geoserver/wms?" + query)
        return status, body

    def transaction(self, body: str) -> tuple[int, bytes]:
        status, raw, _ = self.request(
            "POST",
            "/geoserver/wfs",
            body.encode(),
            content_type="application/xml",
        )
        return status, raw

    def insert_road(self, label: str, category: int) -> tuple[int, bytes]:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<wfs:Transaction service="WFS" version="1.0.0" '
            'xmlns:wfs="http://www.opengis.net/wfs" '
            'xmlns:sf="http://www.openplans.org/spearfish">'
            '<wfs:Insert><sf:roads>'
            f'<sf:cat>{category}</sf:cat><sf:label>{escape(label)}</sf:label>'
            '</sf:roads></wfs:Insert></wfs:Transaction>'
        )
        return self.transaction(body)

    def delete_road(self, feature_id: str) -> tuple[int, bytes]:
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<wfs:Transaction service="WFS" version="1.0.0" '
            'xmlns:wfs="http://www.opengis.net/wfs" '
            'xmlns:ogc="http://www.opengis.net/ogc" '
            'xmlns:sf="http://www.openplans.org/spearfish">'
            '<wfs:Delete typeName="sf:roads"><ogc:Filter>'
            f'<ogc:FeatureId fid="{escape(feature_id)}"/>'
            '</ogc:Filter></wfs:Delete></wfs:Transaction>'
        )
        return self.transaction(body)


def feature_record(document: object, feature_id: str = "") -> dict | None:
    if not isinstance(document, dict):
        return None
    for row in document.get("features") or []:
        if isinstance(row, dict) and (not feature_id or row.get("id") == feature_id):
            return row
    return None
