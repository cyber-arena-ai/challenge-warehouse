"""External checker for GeoServer's WFS, WMS, WFS-T, and layer ACLs."""

from __future__ import annotations

import json
import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import GeoServerClient, feature_record, resolve_host


def _account(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("account missing")
    result = {
        "username": str(value.get("username") or ""),
        "password": str(value.get("password") or ""),
    }
    if not all(result.values()):
        raise ValueError("account incomplete")
    return result


def _find_road(client: GeoServerClient, label: str) -> str:
    escaped = label.replace("'", "''")
    status, document = client.feature(
        "sf:roads", cql_filter=f"label='{escaped}'", count=2
    )
    if status != 200 or not isinstance(document, dict):
        return ""
    rows = [
        row for row in document.get("features") or []
        if isinstance(row, dict)
        and isinstance(row.get("properties"), dict)
        and row["properties"].get("label") == label
    ]
    if len(rows) != 1:
        return ""
    feature_id = rows[0].get("id")
    return feature_id if isinstance(feature_id, str) else ""


class GeoServerChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "geoserver-xpath-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("checker", False, "no exec bridge")
        rc, out = exec_in(target.host, "/arena/facility.py checker-bundle")
        try:
            bundle = json.loads((out or "").strip()) if rc == 0 else {}
            ordinary = _account(bundle["ordinary"])
            guarded = _account(bundle["guarded"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return CheckResult("checker", False, "checker accounts unavailable")

        host = resolve_host(target.host)
        base = f"http://{host}:{target.ports['service']}"
        ordinary_api = GeoServerClient(base, **ordinary)
        guarded_api = GeoServerClient(base, **guarded)
        label = "checker-road-" + secrets.token_hex(12)
        category = 1_000_000 + secrets.randbelow(900_000_000)
        feature_id = ""
        children: list[CheckResult] = []
        try:
            status, body = ordinary_api.capabilities()
            children.append(CheckResult(
                "capabilities", status == 200 and b"WFS_Capabilities" in body,
                f"status={status}",
            ))

            status, document = ordinary_api.feature("topp:states", count=1)
            row = feature_record(document)
            public_ok = (
                status == 200
                and row is not None
                and isinstance(row.get("properties"), dict)
                and bool(row["properties"].get("STATE_NAME"))
            )
            children.append(CheckResult(
                "public_feature", public_ok, f"status={status}"
            ))

            status, body = ordinary_api.property_values(
                "topp:states", "STATE_NAME", count=2
            )
            property_ok = (
                status == 200
                and b"Illinois" in body
                and b"District of Columbia" in body
            )
            children.append(CheckResult(
                "property_value", property_ok, f"status={status}"
            ))

            status, image = ordinary_api.map_png()
            png_ok = status == 200 and image.startswith(b"\x89PNG\r\n\x1a\n")
            children.append(CheckResult("wms_map", png_ok, f"status={status}"))

            insert_status, insert_body = guarded_api.insert_road(label, category)
            inserted = (
                insert_status == 200
                and b"SUCCESS" in insert_body
            )
            feature_id = _find_road(guarded_api, label) if inserted else ""
            children.append(CheckResult(
                "guarded_wfs_t", bool(feature_id), f"status={insert_status}"
            ))

            if feature_id:
                owner_status, owner_doc = guarded_api.feature(
                    "sf:roads", resource_id=feature_id
                )
                owner = feature_record(owner_doc, feature_id)
                owner_ok = (
                    owner_status == 200
                    and owner is not None
                    and isinstance(owner.get("properties"), dict)
                    and owner["properties"].get("label") == label
                )
                denied_status, denied_doc = ordinary_api.feature(
                    "sf:roads", resource_id=feature_id
                )
                denied = not (
                    denied_status == 200
                    and feature_record(denied_doc, feature_id) is not None
                )
                children.append(CheckResult(
                    "layer_boundary", owner_ok and denied,
                    f"authorized={owner_status}, ordinary={denied_status}",
                ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("workflow_exception", False, str(error)))
        finally:
            if feature_id:
                try:
                    guarded_api.delete_road(feature_id)
                except Exception:  # noqa: BLE001
                    pass
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
