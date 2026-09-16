"""External semantic checker for the legitimate OpenTSDB workflow."""

from __future__ import annotations

import json
import secrets
import struct
import time
import zlib

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from .client import OpenTSDBClient
from .config import COHORT_FILE, SERVICE_PORT, sealed_cohort


_WORKLOADS = (
    ("system.cpu.user", "host", "worker"),
    ("http.response.bytes", "route", "endpoint"),
    ("queue.jobs.pending", "queue", "batch"),
    ("service.request.latency", "instance", "node"),
)
_LEGENDS = ("left", "right", "top", "bottom", "center", "out")
_NATIVE_LEGEND_ALIAS = frozenset(("right", "top"))
_DIMENSIONS = ("640x360", "720x480", "800x600", "960x540")
# The seal sits on a box its defender is root over, and the poller that reads it
# serves every team, so the read is bounded. A sealed cohort runs ~110 bytes per
# principal; a truncated one simply fails the seal.
_MAX_SEAL_BYTES = 65536


def _issued_cohort(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    """Read the facility-sealed issued cohort out of root-only bookkeeping."""
    exec_in = target.meta["exec_in_container"]
    rc, output = exec_in(target.host, f"head -c {_MAX_SEAL_BYTES} {COHORT_FILE}")
    if rc != 0:
        raise RuntimeError("OpenTSDB issued cohort is unavailable")
    return sealed_cohort(output or "")


class OpenTSDBChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "opentsdb-metrics-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports.get("service", SERVICE_PORT)
        try:
            cohort = _issued_cohort(target)
            # Every issued principal drives the put/query/UI/graph surfaces an
            # ordinary participant uses, so no per-identity rule can carve one
            # out. The legend, determinism and freshness batteries cost about
            # four seconds more, so one principal per probe carries them: that
            # measured 5-8s at one principal and 15-19s at eight against the 20s
            # interval, where carrying them on every principal costs ~6s each.
            deep_index = secrets.randbelow(len(cohort))
            for index, (principal, token) in enumerate(cohort):
                detail = self._round(
                    OpenTSDBClient(target.host, port, token),
                    deep=index == deep_index,
                )
                if detail is not None:
                    return self._result(False, f"{principal}: {detail}"[:200])
            return self._result(
                True,
                "fresh put/query/UI/Gnuplot legend graph succeeded for "
                f"{len(cohort)} issued principals",
            )
        except (OSError, RuntimeError, ValueError, KeyError, IndexError) as error:
            return self._result(False, f"{type(error).__name__}: {error}")

    def _round(self, client: OpenTSDBClient, *, deep: bool) -> str | None:
        """Run one issued principal's workflow; return a failure detail or None."""
        metric, tag_key, tag_prefix = secrets.choice(_WORKLOADS)
        tag = f"{tag_prefix}-{secrets.token_hex(5)}"
        point_count = secrets.randbelow(3) + 2
        timestamp = int(time.time())
        expected: dict[str, int] = {}
        for index in range(point_count):
            point_timestamp = timestamp - (point_count - index - 1) * 10
            value = secrets.randbelow(900_000) + 100_000
            put_status, put_body, _ = client.put(
                metric,
                tag,
                value,
                tag_key=tag_key,
                timestamp=point_timestamp,
            )
            if put_status != 200 or '"success":1' not in put_body:
                return f"metric put failed: {put_status} {put_body}"
            expected[str(point_timestamp)] = value

        query_status, query_body, points = 0, "", {}
        for attempt in range(12):
            query_status, query_body = client.query(
                metric, tag, timestamp, tag_key=tag_key
            )
            query = json.loads(query_body) if query_status == 200 else []
            points = query[0].get("dps", {}) if isinstance(query, list) and query else {}
            if self._points_match(points, expected):
                break
            if attempt < 11:
                time.sleep(0.25)
        if not self._points_match(points, expected):
            return f"query mismatch: status={query_status} body={query_body}"

        ui_status, ui_body = client.request("/")
        if ui_status != 200 or "OpenTSDB" not in ui_body:
            return f"UI failed: status={ui_status}"

        legend = secrets.choice(_LEGENDS)
        dimensions = secrets.choice(_DIMENSIONS)
        graph_status, graph_body = client.graph(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        graph = json.loads(graph_body) if graph_status == 200 else {}
        if graph.get("plotted") != point_count or graph.get("points") != point_count:
            return f"graph mismatch: status={graph_status} body={graph_body}"
        legend_pixels: dict[str, bytes] = {}
        for position in _LEGENDS if deep else (legend,):
            png_status, png = client.graph_png(
                metric,
                tag,
                timestamp,
                tag_key=tag_key,
                legend=position,
                dimensions=dimensions,
            )
            pixels = self._rendered_pixels(png, dimensions)
            if png_status != 200 or pixels is None:
                return (
                    f"rendered graph mismatch: status={png_status} bytes={len(png)}"
                )
            legend_pixels[position] = pixels
        if not deep:
            return None

        repeat_status, repeat_png = client.graph_png(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        repeat_pixels = self._rendered_pixels(repeat_png, dimensions)
        if repeat_status != 200 or repeat_pixels != legend_pixels[legend]:
            return "rendered graph is not deterministic"
        width, height = (int(value) for value in dimensions.split("x", 1))
        for index, first in enumerate(_LEGENDS):
            for second in _LEGENDS[index + 1 :]:
                if frozenset((first, second)) == _NATIVE_LEGEND_ALIAS:
                    continue
                if self._pixel_difference(
                    legend_pixels[first], legend_pixels[second]
                ) < max(64, width * height // 4000):
                    return f"legend positions {first}/{second} collapsed"

        added_timestamp = timestamp + 20
        added_value = 1_500_000 + secrets.randbelow(500_000)
        put_status, put_body, _ = client.put(
            metric,
            tag,
            added_value,
            tag_key=tag_key,
            timestamp=added_timestamp,
        )
        if put_status != 200 or '"success":1' not in put_body:
            return f"metric update failed: {put_status} {put_body}"
        expected[str(added_timestamp)] = added_value
        for attempt in range(12):
            query_status, query_body = client.query(
                metric, tag, timestamp, tag_key=tag_key
            )
            query = json.loads(query_body) if query_status == 200 else []
            points = query[0].get("dps", {}) if isinstance(query, list) and query else {}
            if self._points_match(points, expected):
                break
            if attempt < 11:
                time.sleep(0.25)
        if not self._points_match(points, expected):
            return f"updated query mismatch: status={query_status} body={query_body}"
        updated_status, updated_body = client.graph(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        updated_graph = json.loads(updated_body) if updated_status == 200 else {}
        if (
            updated_graph.get("plotted") != point_count + 1
            or updated_graph.get("points") != point_count + 1
        ):
            return (
                f"updated graph mismatch: status={updated_status} body={updated_body}"
            )
        updated_png_status, updated_png = client.graph_png(
            metric,
            tag,
            timestamp,
            tag_key=tag_key,
            legend=legend,
            dimensions=dimensions,
        )
        updated_pixels = self._rendered_pixels(updated_png, dimensions)
        if (
            updated_png_status != 200
            or updated_pixels is None
            or self._pixel_difference(legend_pixels[legend], updated_pixels)
            < max(256, width * height // 500)
        ):
            return "rendered graph did not follow fresh data"
        return None

    @staticmethod
    def _points_match(points: object, expected: dict[str, int]) -> bool:
        if not isinstance(points, dict) or set(points) != set(expected):
            return False
        try:
            return all(float(points[key]) == value for key, value in expected.items())
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _rendered_png(body: bytes, dimensions: str) -> bool:
        return OpenTSDBChecker._rendered_pixels(body, dimensions) is not None

    @staticmethod
    def _pixel_difference(first: bytes, second: bytes) -> int:
        if len(first) != len(second) or len(first) % 4:
            return 0
        return sum(
            first[offset : offset + 4] != second[offset : offset + 4]
            for offset in range(0, len(first), 4)
        )

    @staticmethod
    def _rendered_pixels(body: bytes, dimensions: str) -> bytes | None:
        try:
            width, height = (int(value) for value in dimensions.split("x", 1))
        except ValueError:
            return None
        if len(body) <= 1024 or not body.startswith(b"\x89PNG\r\n\x1a\n"):
            return None

        offset = 8
        header: tuple[int, int, int, int, int, int, int] | None = None
        idat = bytearray()
        palette = b""
        transparency: bytes | None = None
        saw_idat = False
        idat_ended = False
        while offset < len(body):
            if offset + 12 > len(body):
                return None
            length = int.from_bytes(body[offset : offset + 4], "big")
            chunk_end = offset + 12 + length
            if chunk_end > len(body):
                return None
            kind = body[offset + 4 : offset + 8]
            data = body[offset + 8 : offset + 8 + length]
            expected_crc = int.from_bytes(body[offset + 8 + length : chunk_end], "big")
            if (
                any(not chr(value).isalpha() or value > 127 for value in kind)
                or kind[2] & 32
                or zlib.crc32(data, zlib.crc32(kind)) & 0xFFFFFFFF != expected_crc
            ):
                return None

            if header is None:
                if kind != b"IHDR" or length != 13:
                    return None
                header = struct.unpack(">IIBBBBB", data)
                (
                    png_width,
                    png_height,
                    depth,
                    color,
                    compression,
                    filtering,
                    interlace,
                ) = header
                valid_depths = {
                    0: {1, 2, 4, 8, 16},
                    2: {8, 16},
                    3: {1, 2, 4, 8},
                    4: {8, 16},
                    6: {8, 16},
                }
                if (
                    (png_width, png_height) != (width, height)
                    or depth not in valid_depths.get(color, set())
                    or compression != 0
                    or filtering != 0
                    or interlace != 0
                ):
                    return None
            elif kind == b"IHDR":
                return None
            elif kind == b"PLTE":
                color, depth = header[3], header[2]
                if (
                    palette
                    or saw_idat
                    or color in {0, 4}
                    or not length
                    or length % 3
                    or length > 3 * (2**depth if color == 3 else 256)
                ):
                    return None
                palette = data
            elif kind == b"tRNS":
                color = header[3]
                entries = len(palette) // 3
                if (
                    transparency is not None
                    or saw_idat
                    or color in {4, 6}
                    or (color == 0 and length != 2)
                    or (color == 2 and length != 6)
                    or (color == 3 and (not palette or not 0 < length <= entries))
                ):
                    return None
                transparency = data
            elif kind == b"IDAT":
                if idat_ended or (header[3] == 3 and not palette):
                    return None
                saw_idat = True
                idat.extend(data)
            elif kind == b"IEND":
                if length or not saw_idat or not idat or chunk_end != len(body):
                    return None
                break
            elif not kind or kind[0] & 32 == 0:
                return None
            elif saw_idat:
                idat_ended = True
            offset = chunk_end
        else:
            return None

        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[header[3]]
        row_bytes = (width * channels * header[2] + 7) // 8
        expected_size = height * (row_bytes + 1)
        try:
            decompressor = zlib.decompressobj()
            pixels = decompressor.decompress(bytes(idat), expected_size + 1)
        except zlib.error:
            return None
        if (
            len(pixels) != expected_size
            or not decompressor.eof
            or decompressor.unused_data
            or decompressor.unconsumed_tail
        ):
            return None

        bytes_per_pixel = max(1, (channels * header[2] + 7) // 8)
        rows: list[bytes] = []
        previous = bytes(row_bytes)
        for row_index in range(height):
            start = row_index * (row_bytes + 1)
            filter_type = pixels[start]
            if filter_type > 4:
                return None
            row = bytearray(pixels[start + 1 : start + row_bytes + 1])
            for index, value in enumerate(row):
                left = row[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
                above = previous[index]
                upper_left = (
                    previous[index - bytes_per_pixel]
                    if index >= bytes_per_pixel
                    else 0
                )
                if filter_type == 1:
                    value += left
                elif filter_type == 2:
                    value += above
                elif filter_type == 3:
                    value += (left + above) // 2
                elif filter_type == 4:
                    estimate = left + above - upper_left
                    distances = (
                        abs(estimate - left),
                        abs(estimate - above),
                        abs(estimate - upper_left),
                    )
                    value += (left, above, upper_left)[distances.index(min(distances))]
                row[index] = value & 0xFF
            previous = bytes(row)
            rows.append(previous)

        depth, color = header[2], header[3]

        def samples_at(row: bytes, column: int) -> tuple[int, ...]:
            if depth < 8:
                bit_offset = column * depth
                shift = 8 - depth - bit_offset % 8
                return ((row[bit_offset // 8] >> shift) & ((1 << depth) - 1),)
            sample_bytes = depth // 8
            start = column * channels * sample_bytes
            return tuple(
                int.from_bytes(row[index : index + sample_bytes], "big")
                for index in range(start, start + channels * sample_bytes, sample_bytes)
            )

        def scale(sample: int) -> int:
            maximum = (1 << depth) - 1
            return (sample * 255 + maximum // 2) // maximum

        def displayed_at(row: bytes, column: int) -> tuple[int, int, int, int] | None:
            samples = samples_at(row, column)
            alpha = 255
            if color == 0:
                red = green = blue = scale(samples[0])
                if transparency is not None and samples[0] == int.from_bytes(
                    transparency, "big"
                ):
                    alpha = 0
            elif color == 2:
                red, green, blue = (scale(sample) for sample in samples)
                if transparency is not None and samples == struct.unpack(
                    ">HHH", transparency
                ):
                    alpha = 0
            elif color == 3:
                palette_offset = samples[0] * 3
                if palette_offset + 3 > len(palette):
                    return None
                red, green, blue = palette[palette_offset : palette_offset + 3]
                if transparency is not None and samples[0] < len(transparency):
                    alpha = transparency[samples[0]]
            elif color == 4:
                red = green = blue = scale(samples[0])
                alpha = scale(samples[1])
            else:
                red, green, blue, alpha = (scale(sample) for sample in samples)
            return (
                (red * alpha + 255 * (255 - alpha) + 127) // 255,
                (green * alpha + 255 * (255 - alpha) + 127) // 255,
                (blue * alpha + 255 * (255 - alpha) + 127) // 255,
                255,
            )

        background = displayed_at(rows[0], 0)
        if background is None:
            return None
        distinct = {background}
        displayed = bytearray()
        changed = 0
        chromatic = 0
        changed_rows: set[int] = set()
        changed_columns: set[int] = set()
        for row_index, row in enumerate(rows):
            for column in range(width):
                pixel = displayed_at(row, column)
                if pixel is None:
                    return None
                displayed.extend(pixel)
                if len(distinct) < 8:
                    distinct.add(pixel)
                if pixel == background:
                    continue
                changed += 1
                changed_rows.add(row_index)
                changed_columns.add(column)
                red, green, blue = pixel[:3]
                if red != green or green != blue:
                    chromatic += 1

        meaningful = (
            len(distinct) >= 3
            and changed >= max(64, width * height // 1000)
            and chromatic >= 8
            and len(changed_rows) >= max(8, height // 32)
            and len(changed_columns) >= max(8, width // 32)
        )
        return bytes(displayed) if meaningful else None

    @staticmethod
    def _result(passed: bool, detail: str) -> CheckResult:
        return CheckResult(name="checker", passed=passed, detail=detail[-200:])
