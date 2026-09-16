"""Pure helpers for indistinguishable GeoServer road validation."""

from __future__ import annotations

import secrets
import string
import struct
import xml.etree.ElementTree as ET
import zlib
from decimal import Decimal, InvalidOperation
from math import hypot
from typing import Sequence
from urllib.parse import quote, urlencode
from xml.sax.saxutils import escape

GEOMETRY_X = (591000, 608000)
GEOMETRY_Y = (4915500, 4926500)
GEOMETRY_SPAN = (500, 1400)
WMS_WIDTH = 170
WMS_HEIGHT = 110
WMS_BBOX = ",".join(map(str, (
    GEOMETRY_X[0], GEOMETRY_Y[0], GEOMETRY_X[1], GEOMETRY_Y[1],
)))

_PROOF_ALPHABET = string.ascii_uppercase + string.digits
_WFS_NAMESPACE = "http://www.opengis.net/wfs/2.0"
_OWS_NAMESPACE = "http://www.opengis.net/ows/1.1"
_FEATURE_NAMESPACES = {
    "sf": "http://www.openplans.org/spearfish",
    "topp": "http://www.openplans.org/topp",
}
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


def ordinary_headers() -> dict[str, str]:
    major = 126 + secrets.randbelow(20)
    platform = secrets.choice(_HTTP_PLATFORMS)
    return {
        "Accept": secrets.choice(_HTTP_ACCEPTS),
        "User-Agent": (
            f"Mozilla/5.0 ({platform}; rv:{major}.0) "
            f"Gecko/20100101 Firefox/{major}.0"
        ),
    }


def _query(params: dict[str, object]) -> str:
    return urlencode(params, quote_via=quote)


def road_feature_path(cql_filter: str, count: int = 3) -> str:
    return "/wfs?" + _query({
        "service": "WFS",
        "version": "2.0.0",
        "request": "GetFeature",
        "typeNames": "sf:roads",
        "outputFormat": "application/json",
        "count": count,
        "CQL_FILTER": cql_filter,
    })


def road_insert_document(
    label: str,
    category: int,
    geometry: Sequence[Sequence[int]],
) -> str:
    coordinates = " ".join(f"{point[0]},{point[1]}" for point in geometry)
    return (
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


def road_delete_document(category: int, label: str) -> str:
    return (
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


def road_property_document(
    property_name: str, category: int, label: str,
) -> str:
    return (
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


def map_path(
    width: int,
    height: int,
    *,
    layer: str,
    srs: str,
    bbox: str,
    cql_filter: str = "",
    transparent: bool = False,
) -> str:
    params: dict[str, object] = {
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
    return "/wms?" + _query(params)


def road_label() -> str:
    body = "".join(secrets.choice(_PROOF_ALPHABET) for _ in range(32))
    return f"FLAG{{{body}}}"


def cql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def road_filter(category: int, label: str = "") -> str:
    expression = f"cat={category}"
    if label:
        expression += " AND label=" + cql_string(label)
    return expression


def valid_geometry(value: object) -> bool:
    return (
        isinstance(value, (list, tuple))
        and len(value) == 2
        and all(
            isinstance(point, (list, tuple))
            and len(point) == 2
            and all(
                isinstance(item, int) and not isinstance(item, bool)
                for item in point
            )
            for point in value
        )
        and value[0] != value[1]
        and all(GEOMETRY_X[0] <= point[0] <= GEOMETRY_X[1] for point in value)
        and all(GEOMETRY_Y[0] <= point[1] <= GEOMETRY_Y[1] for point in value)
    )


def geometry_matches(document: object, expected: Sequence[Sequence[int]]) -> bool:
    if not isinstance(document, dict) or document.get("type") != "MultiLineString":
        return False
    coordinates = document.get("coordinates")
    return (
        isinstance(coordinates, list)
        and len(coordinates) == 1
        and isinstance(coordinates[0], list)
        and len(coordinates[0]) == 2
        and all(
            isinstance(point, list)
            and len(point) >= 2
            and point[0] == expected[index][0]
            and point[1] == expected[index][1]
            for index, point in enumerate(coordinates[0])
        )
    )


def random_geometry() -> list[list[int]]:
    span = GEOMETRY_SPAN[0] + secrets.randbelow(
        GEOMETRY_SPAN[1] - GEOMETRY_SPAN[0] + 1
    )
    center_x = GEOMETRY_X[0] + span + secrets.randbelow(
        GEOMETRY_X[1] - GEOMETRY_X[0] - 2 * span + 1
    )
    center_y = GEOMETRY_Y[0] + span + secrets.randbelow(
        GEOMETRY_Y[1] - GEOMETRY_Y[0] - 2 * span + 1
    )
    slope = -1 if secrets.randbelow(2) else 1
    return [
        [center_x - span, center_y - slope * span],
        [center_x + span, center_y + slope * span],
    ]


def single_property_value(
    document: bytes, type_name: str, property_name: str,
) -> str | None:
    try:
        root = ET.fromstring(document)
    except (ET.ParseError, ValueError):
        return None
    namespace = _FEATURE_NAMESPACES.get(type_name.partition(":")[0])
    if namespace is None or root.tag != f"{{{_WFS_NAMESPACE}}}ValueCollection":
        return None
    if any("Exception" in node.tag.rpartition("}")[2] for node in root.iter()):
        return None
    members = list(root)
    if len(members) != 1 or members[0].tag != f"{{{_WFS_NAMESPACE}}}member":
        return None
    values = list(members[0])
    if (
        len(values) != 1
        or values[0].tag != f"{{{namespace}}}{property_name}"
        or list(values[0])
        or root.attrib.get("numberReturned", "1") != "1"
        or root.attrib.get("numberMatched", "1") != "1"
    ):
        return None
    return values[0].text


def native_layer_denial(status: int, document: bytes | str) -> bool:
    if status in (401, 403):
        return True
    if status != 400:
        return False
    try:
        root = ET.fromstring(document)
    except (ET.ParseError, ValueError):
        return False
    if root.tag != f"{{{_OWS_NAMESPACE}}}ExceptionReport":
        return False
    exceptions = list(root)
    if len(exceptions) != 1:
        return False
    exception = exceptions[0]
    if (
        exception.tag != f"{{{_OWS_NAMESPACE}}}Exception"
        or exception.attrib.get("exceptionCode") != "InvalidParameterValue"
        or exception.attrib.get("locator") != "typeName"
    ):
        return False
    texts = list(exception)
    return (
        len(texts) == 1
        and texts[0].tag == f"{{{_OWS_NAMESPACE}}}ExceptionText"
        and "".join(texts[0].itertext()).strip()
        == "Feature type sf:roads unknown"
    )


def property_matches(
    document: bytes,
    type_name: str,
    property_name: str,
    expected: str | int | float,
) -> bool:
    actual = single_property_value(document, type_name, property_name)
    if actual is None:
        return False
    if isinstance(expected, str):
        return actual == expected
    try:
        actual_number = Decimal(actual)
        expected_number = Decimal(str(expected))
    except InvalidOperation:
        return False
    return (
        actual_number.is_finite()
        and expected_number.is_finite()
        and actual_number == expected_number
    )


def png_pixels(
    document: bytes, width: int, height: int,
) -> tuple[int, int, bytes] | None:
    if not document.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    position = 8
    header: tuple[int, int, int, int, int, int, int] | None = None
    compressed = bytearray()
    ended = False
    while position + 12 <= len(document):
        length = int.from_bytes(document[position:position + 4], "big")
        chunk_end = position + 12 + length
        if chunk_end > len(document):
            return None
        chunk_type = document[position + 4:position + 8]
        payload = document[position + 8:position + 8 + length]
        checksum = int.from_bytes(document[position + 8 + length:chunk_end], "big")
        if zlib.crc32(chunk_type + payload) & 0xFFFFFFFF != checksum:
            return None
        if header is None and chunk_type != b"IHDR":
            return None
        if chunk_type == b"IHDR":
            if header is not None or length != 13:
                return None
            header = struct.unpack(">IIBBBBB", payload)
        elif chunk_type == b"IDAT":
            compressed.extend(payload)
        elif chunk_type == b"IEND":
            if length != 0 or chunk_end != len(document):
                return None
            ended = True
            break
        position = chunk_end
    if header is None or not compressed or not ended:
        return None
    (
        actual_width, actual_height, depth, color,
        compression, filtering, interlace,
    ) = header
    valid_depths = {
        0: {1, 2, 4, 8, 16},
        2: {8, 16},
        3: {1, 2, 4, 8},
        4: {8, 16},
        6: {8, 16},
    }
    if (
        (actual_width, actual_height) != (width, height)
        or depth not in valid_depths.get(color, set())
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        return None
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    row_bytes = (width * channels * depth + 7) // 8
    expected_size = height * (row_bytes + 1)
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(bytes(compressed), expected_size + 1)
    except zlib.error:
        return None
    if (
        len(pixels) != expected_size
        or not decoder.eof
        or decoder.unconsumed_tail
        or decoder.unused_data
    ):
        return None
    bytes_per_pixel = max(1, (channels * depth + 7) // 8)
    previous = bytearray(row_bytes)
    decoded = bytearray()
    for row_index in range(height):
        offset = row_index * (row_bytes + 1)
        filter_type = pixels[offset]
        if filter_type > 4:
            return None
        row = bytearray(pixels[offset + 1:offset + 1 + row_bytes])
        for index in range(row_bytes):
            left = row[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            above = previous[index]
            upper_left = (
                previous[index - bytes_per_pixel]
                if index >= bytes_per_pixel else 0
            )
            if filter_type == 1:
                row[index] = (row[index] + left) & 0xFF
            elif filter_type == 2:
                row[index] = (row[index] + above) & 0xFF
            elif filter_type == 3:
                row[index] = (row[index] + ((left + above) // 2)) & 0xFF
            elif filter_type == 4:
                estimate = left + above - upper_left
                distances = (
                    abs(estimate - left), abs(estimate - above),
                    abs(estimate - upper_left),
                )
                predictor = (left, above, upper_left)[distances.index(min(distances))]
                row[index] = (row[index] + predictor) & 0xFF
        decoded.extend(row)
        previous = row
    return depth, color, bytes(decoded)


def valid_png(document: bytes, width: int, height: int) -> bool:
    return png_pixels(document, width, height) is not None


def render_matches(
    selected: bytes,
    absent: bytes,
    width: int,
    height: int,
    geometry: Sequence[Sequence[int]],
) -> bool:
    selected_pixels = png_pixels(selected, width, height)
    absent_pixels = png_pixels(absent, width, height)
    if (
        selected_pixels is None
        or absent_pixels is None
        or selected_pixels[:2] != (8, 6)
        or absent_pixels[:2] != (8, 6)
    ):
        return False
    selected_visible = {
        (index % width, index // width)
        for index, alpha in enumerate(selected_pixels[2][3::4])
        if alpha
    }
    if any(absent_pixels[2][3::4]) or not (
        4 <= len(selected_visible) <= width * height // 8
    ):
        return False

    def projected(point: Sequence[int]) -> tuple[float, float]:
        return (
            (point[0] - GEOMETRY_X[0]) * (width - 1)
            / (GEOMETRY_X[1] - GEOMETRY_X[0]),
            (GEOMETRY_Y[1] - point[1]) * (height - 1)
            / (GEOMETRY_Y[1] - GEOMETRY_Y[0]),
        )

    start, end = map(projected, geometry)
    delta_x = end[0] - start[0]
    delta_y = end[1] - start[1]
    length_squared = delta_x * delta_x + delta_y * delta_y

    def distance(point: tuple[int, int]) -> float:
        offset_x = point[0] - start[0]
        offset_y = point[1] - start[1]
        amount = max(0.0, min(
            1.0, (offset_x * delta_x + offset_y * delta_y) / length_squared
        ))
        return hypot(
            point[0] - (start[0] + amount * delta_x),
            point[1] - (start[1] + amount * delta_y),
        )

    close = sum(distance(point) <= 4.0 for point in selected_visible)
    return (
        close * 10 >= len(selected_visible) * 9
        and all(
            any(
                hypot(x - endpoint[0], y - endpoint[1]) <= 5.0
                for x, y in selected_visible
            )
            for endpoint in (start, end)
        )
    )
