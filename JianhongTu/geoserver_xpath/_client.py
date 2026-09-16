"""Small stdlib GeoServer WFS/WMS client shared by probes and the PoV."""

from __future__ import annotations

import base64
import json
import secrets
import socket
import urllib.error
import urllib.parse
import urllib.request
from xml.sax.saxutils import escape, quoteattr

TIMEOUT = 20

try:
    from .image.road_protocol import (
        map_path as _shared_map_path,
        ordinary_headers as _ordinary_headers,
        road_delete_document as _shared_road_delete_document,
        road_feature_path as _shared_road_feature_path,
        road_insert_document as _shared_road_insert_document,
        road_property_document as _shared_road_property_document,
    )
except ImportError:  # Standalone attacker copy uses only the generic client.
    _HTTP_PLATFORMS = (
        "X11; Linux x86_64",
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
    )
    _HTTP_ACCEPTS = (
        "*/*",
        "application/json,application/xml;q=0.9,*/*;q=0.8",
        "text/xml,application/xml;q=0.9,*/*;q=0.7",
    )

    def _ordinary_headers() -> dict[str, str]:
        major = 126 + secrets.randbelow(20)
        platform = secrets.choice(_HTTP_PLATFORMS)
        return {
            "Accept": secrets.choice(_HTTP_ACCEPTS),
            "User-Agent": (
                f"Mozilla/5.0 ({platform}; rv:{major}.0) "
                f"Gecko/20100101 Firefox/{major}.0"
            ),
        }

    _shared_map_path = None
    _shared_road_delete_document = None
    _shared_road_feature_path = None
    _shared_road_insert_document = None
    _shared_road_property_document = None


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
        headers = _ordinary_headers()
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

    def public_resource(self, path: str) -> tuple[int, bytes]:
        status, body, _ = self.request("GET", path)
        return status, body

    def put_resource(self, path: str, body: bytes) -> tuple[int, bytes]:
        status, raw, _ = self.request(
            "PUT", path, body, content_type="application/octet-stream"
        )
        return status, raw

    def delete_resource(self, path: str) -> tuple[int, bytes]:
        status, raw, _ = self.request("DELETE", path)
        return status, raw

    def feature(
        self,
        type_name: str,
        *,
        resource_id: str = "",
        cql_filter: str = "",
        count: int = 1,
    ) -> tuple[int, object]:
        if (
            type_name == "sf:roads"
            and cql_filter
            and not resource_id
            and _shared_road_feature_path is not None
        ):
            path = "/geoserver" + _shared_road_feature_path(cql_filter, count)
            status, body, _ = self.request("GET", path)
            try:
                return status, json.loads(body)
            except ValueError:
                return status, body.decode(errors="replace")

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

    def property_value(
        self, type_name: str, property_name: str, resource_id: str
    ) -> tuple[int, bytes]:
        namespaces = {
            "sf": "http://www.openplans.org/spearfish",
            "topp": "http://www.openplans.org/topp",
        }
        prefix = type_name.partition(":")[0]
        namespace = namespaces.get(prefix)
        if not namespace:
            raise ValueError("unsupported feature namespace")
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<wfs:GetPropertyValue service="WFS" version="2.0.0" '
            'xmlns:wfs="http://www.opengis.net/wfs/2.0" '
            'xmlns:fes="http://www.opengis.net/fes/2.0" '
            f'xmlns:{prefix}={quoteattr(namespace)}>'
            f'<wfs:Query typeNames={quoteattr(type_name)}><fes:Filter>'
            f'<fes:ResourceId rid={quoteattr(resource_id)}/>'
            '</fes:Filter></wfs:Query>'
            f'<wfs:ValueReference>{escape(property_name)}</wfs:ValueReference>'
            '</wfs:GetPropertyValue>'
        )
        status, raw, _ = self.request(
            "POST", "/geoserver/wfs", body.encode(), content_type="application/xml"
        )
        return status, raw

    def road_property_value(
        self, property_name: str, category: int, label: str,
    ) -> tuple[int, bytes]:
        body = _shared_road_property_document(
            property_name, category, label
        ) if _shared_road_property_document is not None else (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<wfs:GetPropertyValue service="WFS" version="2.0.0" '
            'xmlns:wfs="http://www.opengis.net/wfs/2.0" '
            'xmlns:fes="http://www.opengis.net/fes/2.0" '
            'xmlns:sf="http://www.openplans.org/spearfish">'
            '<wfs:Query typeNames="sf:roads"><fes:Filter><fes:And>'
            '<fes:PropertyIsEqualTo><fes:ValueReference>cat</fes:ValueReference>'
            f'<fes:Literal>{category}</fes:Literal></fes:PropertyIsEqualTo>'
            '<fes:PropertyIsEqualTo><fes:ValueReference>label</fes:ValueReference>'
            f'<fes:Literal>{escape(label)}</fes:Literal></fes:PropertyIsEqualTo>'
            '</fes:And></fes:Filter></wfs:Query>'
            f'<wfs:ValueReference>{escape(property_name)}</wfs:ValueReference>'
            '</wfs:GetPropertyValue>'
        )
        status, raw, _ = self.request(
            "POST", "/geoserver/wfs", body.encode(), content_type="application/xml"
        )
        return status, raw

    def map_png(
        self,
        width: int,
        height: int,
        *,
        layer: str = "topp:states",
        srs: str = "EPSG:4326",
        bbox: str = "-180,-90,180,90",
        cql_filter: str = "",
        transparent: bool = False,
    ) -> tuple[int, bytes]:
        if _shared_map_path is not None:
            path = "/geoserver" + _shared_map_path(
                width, height, layer=layer, srs=srs, bbox=bbox,
                cql_filter=cql_filter, transparent=transparent,
            )
        else:
            params = {
                "service": "WMS",
                "version": "1.1.1",
                "request": "GetMap",
                "layers": layer,
                "styles": "",
                "srs": srs,
                "bbox": bbox,
                "width": width,
                "height": height,
                "format": "image/png",
            }
            if transparent:
                params["transparent"] = "true"
            if cql_filter:
                params["CQL_FILTER"] = cql_filter
            path = "/geoserver/wms?" + self._query(params)
        status, body, _ = self.request("GET", path)
        return status, body

    def transaction(self, body: str) -> tuple[int, bytes]:
        status, raw, _ = self.request(
            "POST",
            "/geoserver/wfs",
            body.encode(),
            content_type="application/xml",
        )
        return status, raw

    def insert_road(
        self,
        label: str,
        category: int,
        geometry: tuple[tuple[int, int], tuple[int, int]],
    ) -> tuple[int, bytes]:
        if _shared_road_insert_document is not None:
            body = _shared_road_insert_document(label, category, geometry)
        else:
            coordinates = " ".join(f"{x},{y}" for x, y in geometry)
            body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<wfs:Transaction service="WFS" version="1.0.0" '
                'xmlns:wfs="http://www.opengis.net/wfs" '
                'xmlns:gml="http://www.opengis.net/gml" '
                'xmlns:sf="http://www.openplans.org/spearfish">'
                '<wfs:Insert><sf:roads>'
                '<sf:the_geom><gml:MultiLineString srsName="EPSG:26713">'
                '<gml:lineStringMember><gml:LineString>'
                f'<gml:coordinates>{coordinates}</gml:coordinates>'
                '</gml:LineString></gml:lineStringMember>'
                '</gml:MultiLineString></sf:the_geom>'
                f'<sf:cat>{category}</sf:cat><sf:label>{escape(label)}</sf:label>'
                '</sf:roads></wfs:Insert></wfs:Transaction>'
            )
        return self.transaction(body)

    def delete_road(self, label: str, category: int) -> tuple[int, bytes]:
        body = _shared_road_delete_document(
            category, label
        ) if _shared_road_delete_document is not None else (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<wfs:Transaction service="WFS" version="1.0.0" '
            'xmlns:wfs="http://www.opengis.net/wfs" '
            'xmlns:ogc="http://www.opengis.net/ogc" '
            'xmlns:sf="http://www.openplans.org/spearfish">'
            '<wfs:Delete typeName="sf:roads"><ogc:Filter><ogc:And>'
            '<ogc:PropertyIsEqualTo><ogc:PropertyName>cat</ogc:PropertyName>'
            f'<ogc:Literal>{category}</ogc:Literal></ogc:PropertyIsEqualTo>'
            '<ogc:PropertyIsEqualTo><ogc:PropertyName>label</ogc:PropertyName>'
            f'<ogc:Literal>{escape(label)}</ogc:Literal></ogc:PropertyIsEqualTo>'
            '</ogc:And></ogc:Filter></wfs:Delete></wfs:Transaction>'
        )
        return self.transaction(body)


def feature_record(document: object, feature_id: str = "") -> dict | None:
    if not isinstance(document, dict):
        return None
    for row in document.get("features") or []:
        if isinstance(row, dict) and (not feature_id or row.get("id") == feature_id):
            return row
    return None
