"""External checker for the normal shared-project REST and CalDAV workflow."""

from __future__ import annotations

import secrets

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import VikunjaApi, resolve_host


def _related_ids(task: dict | None) -> set[int]:
    related = (task or {}).get("related_tasks") or {}
    return {
        item["id"] for items in related.values() for item in (items or [])
        if isinstance(item, dict) and isinstance(item.get("id"), int)
    }


class VikunjaChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "vikunja-private-task-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        api = VikunjaApi(
            f"http://{resolve_host(target.host)}:{target.ports['service']}")
        suffix = secrets.token_hex(6)
        owner = "checko" + suffix
        reader = "checkr" + suffix
        owner_password = "O1!" + secrets.token_hex(16)
        reader_password = "R1!" + secrets.token_hex(16)
        children: list[CheckResult] = []
        try:
            registrations = [
                api.register(owner, owner + "@arena.invalid", owner_password),
                api.register(reader, reader + "@arena.invalid", reader_password),
            ]
            owner_token = api.login(owner, owner_password)
            reader_token = api.login(reader, reader_password)
            ok = registrations == [200, 200] and bool(owner_token and reader_token)
            children.append(CheckResult("accounts", ok,
                                        f"register={registrations}, login={bool(owner_token and reader_token)}"))
            if not ok:
                return CheckResult("checker", False, children=children)

            shared = api.create_project(owner_token, "Checker shared " + suffix)
            private = api.create_project(owner_token, "Checker private " + suffix)
            shared_task = api.create_task(owner_token, int(shared["id"]),
                                          "Checker task " + suffix, "ordinary")
            peer = api.create_task(owner_token, int(shared["id"]),
                                   "Checker peer " + suffix, "ordinary peer")
            private_task = api.create_task(owner_token, int(private["id"]),
                                           "Checker guarded " + suffix, "not public")
            share_status = api.share_project(owner_token, int(shared["id"]), reader)
            relation_statuses = [
                api.relate(owner_token, int(shared_task["id"]), int(peer["id"])),
                api.relate(owner_token, int(shared_task["id"]), int(private_task["id"])),
            ]
            children.append(CheckResult(
                "owner_setup",
                share_status in (200, 201) and all(s in (200, 201) for s in relation_statuses),
                f"share={share_status}, relations={relation_statuses}",
            ))

            owner_status, owner_task, _ = api.get_task(
                owner_token, int(shared_task["id"]))
            owner_related = _related_ids(owner_task)
            expected_owner = {int(peer["id"]), int(private_task["id"])}
            children.append(CheckResult(
                "owner_relations",
                owner_status == 200 and expected_owner <= owner_related,
                f"task={owner_status}, both_relations={expected_owner <= owner_related}",
            ))

            shared_status, task, _ = api.get_task(reader_token, int(shared_task["id"]))
            related_ids = _related_ids(task)
            children.append(CheckResult(
                "shared_read", shared_status == 200 and int(peer["id"]) in related_ids,
                f"task={shared_status}, legitimate_relation={int(peer['id']) in related_ids}",
            ))

            denied_status, _, _ = api.get_task(reader_token, int(private_task["id"]))
            create_status, _ = api.request(
                "PUT", f"/api/v1/projects/{shared['id']}/tasks", token=reader_token,
                body={"title": "must be denied"})
            children.append(CheckResult(
                "boundaries", denied_status in (403, 404) and create_status == 403,
                f"private_read={denied_status}, shared_write={create_status}",
            ))

            propfind_status, hrefs = api.caldav_hrefs(
                reader, reader_password, int(shared["id"]))
            caldav_ok = False
            for href in hrefs:
                status, raw = api.caldav_get(reader, reader_password, href)
                if status == 200 and ("Checker task " + suffix).encode() in raw:
                    caldav_ok = True
                    break
            children.append(CheckResult(
                "caldav", propfind_status == 207 and caldav_ok,
                f"PROPFIND={propfind_status}, task_get={caldav_ok}",
            ))
        except Exception as error:  # noqa: BLE001
            children.append(CheckResult("exception", False, str(error)))
        return CheckResult("checker", all(child.passed for child in children),
                           children=children)
