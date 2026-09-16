"""Native principal provisioning and failure-safe WRITE placement for Jenkins."""

from __future__ import annotations

import base64
import json
import secrets
import shlex
import time
import urllib.parse
from collections.abc import Mapping
from typing import Any

from challenges.interface import (
    BaselinePrincipal,
    Flag,
    FlagHandler,
    FlagObservation,
    ObservationStatus,
    StateReadStatus,
    VulboxTarget,
    read_authoritative_state,
)

from ._client import (
    JenkinsClient,
    checker_job_xml,
    get_description,
    protected_job_xml,
    set_description,
)
from ._ids import (
    ANCHOR_REGION,
    OBJECTIVE_REGION,
    POOL_NAMES,
    STORE,
    checker_principals,
    pack_handle,
    pool_cover,
    participant_inventory_description,
    participant_inventory_job,
    principal_credentials,
    principal_job,
    public_locator,
    round_context,
    unpack_handle,
)


PRIVATE_DIR = "/var/lib/cyberarena-private"
JOURNAL_PATH = f"{PRIVATE_DIR}/objective-journal.json"
ISSUED_PATH = f"{PRIVATE_DIR}/objective-issued"
ISSUED_VALUE = "jenkins-controller-write-v1"
BUILD_TIMEOUT = 90


def _empty_journal() -> dict[str, Any]:
    return {"v": 1, "current": None, "previous": None, "pending": None}


def _b64(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _seed_participant_build(client: JenkinsClient, job: str) -> int:
    quoted = urllib.parse.quote(job)
    status, document = client.json(f"/job/{quoted}/api/json?tree=nextBuildNumber")
    if status != 200 or not isinstance(document, dict):
        raise RuntimeError("participant Pipeline build state is unavailable")
    expected = document.get("nextBuildNumber")
    if not isinstance(expected, int) or isinstance(expected, bool):
        raise RuntimeError("participant Pipeline build number is malformed")
    token = secrets.token_hex(32)
    status, _ = client.request(
        f"/job/{quoted}/buildWithParameters?"
        + urllib.parse.urlencode({"TOKEN": token}),
        data=b"",
        headers=client.crumb,
    )
    if status not in (200, 201, 302):
        raise RuntimeError("participant Pipeline seed build failed")
    deadline = time.monotonic() + BUILD_TIMEOUT
    while time.monotonic() < deadline:
        status, build = client.json(f"/job/{quoted}/{expected}/api/json")
        if status == 200 and isinstance(build, dict) and build.get("building") is False:
            if build.get("result") != "SUCCESS":
                raise RuntimeError("participant Pipeline seed build failed")
            artifact_status, artifact = client.request(
                f"/job/{quoted}/{expected}/artifact/probe.txt"
            )
            link_status, link = client.request(
                f"/job/{quoted}/{expected}/artifact/safe-link/value.txt"
            )
            if (
                artifact_status != 200
                or artifact.decode(errors="replace") != token
                or link_status != 200
                or link.decode(errors="replace") != token
            ):
                raise RuntimeError("participant Pipeline seed artifact is invalid")
            return expected
        if status not in (200, 404):
            raise RuntimeError("participant Pipeline seed build is unavailable")
        time.sleep(1)
    raise RuntimeError("participant Pipeline seed build timed out")


def _valid_generation(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if set(value) != {
        "anchor",
        "audit",
        "context",
        "cover",
        "handle",
        "region",
        "slot",
        "target",
        "token",
    }:
        return False
    handle = value.get("handle")
    payload = unpack_handle(handle)
    return (
        payload is not None
        and value.get("context") == payload.get("context")
        and value.get("target") == payload.get("target")
        and value.get("region") == payload.get("region")
        and value.get("token") == payload.get("token")
        and value.get("anchor") == payload.get("anchor")
        and value.get("audit") == payload.get("audit")
        and value.get("slot") == payload.get("slot")
        and isinstance(value.get("cover"), str)
        and bool(value["cover"])
    )


def _parse_journal(raw: str) -> dict[str, Any]:
    try:
        journal = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("objective journal is malformed") from error
    if (
        not isinstance(journal, dict)
        or set(journal) != {"v", "current", "previous", "pending"}
        or journal.get("v") != 1
        or any(
            journal.get(key) is not None and not _valid_generation(journal.get(key))
            for key in ("current", "previous", "pending")
        )
        or all(journal.get(key) is None for key in ("current", "previous", "pending"))
    ):
        raise RuntimeError("objective journal is malformed")
    targets = [
        generation["target"]
        for key in ("current", "previous", "pending")
        if isinstance((generation := journal.get(key)), dict)
    ]
    if len(targets) != len(set(targets)):
        raise RuntimeError("objective journal has duplicate targets")
    return journal


class JenkinsFlagHandler(FlagHandler):
    @property
    def name(self) -> str:
        return "jenkins-controller-write-flag-handler"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    @staticmethod
    def _exec(target: VulboxTarget, command: str) -> str:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            raise RuntimeError("no facility exec bridge")
        rc, output = exec_in(target.host, command)
        if rc != 0:
            raise RuntimeError("Jenkins facility operation failed")
        return output or ""

    @staticmethod
    def _team_id(target: VulboxTarget) -> str:
        team_id = target.meta.get("team_id")
        if not isinstance(team_id, str) or not team_id:
            raise RuntimeError("target team identity is unavailable")
        return team_id

    def _guarded_client(self, target: VulboxTarget) -> JenkinsClient:
        output = self._exec(target, "/arena/facility.py admin-credentials")
        try:
            document = json.loads(output.strip())
            username = document["username"]
            password = document["password"]
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Jenkins administration unavailable") from error
        return JenkinsClient(
            f"http://{target.host}:{target.ports['web']}", username, password
        )

    def _load_journal(self, target: VulboxTarget) -> dict[str, Any]:
        marker = self._exec(
            target,
            f"if [ ! -e {shlex.quote(ISSUED_PATH)} ]; then printf missing; "
            f"elif [ -f {shlex.quote(ISSUED_PATH)} ]; then printf 'file\\n'; "
            f"cat {shlex.quote(ISSUED_PATH)}; else printf invalid; fi",
        )
        if marker == "missing":
            issued = False
        elif marker == f"file\n{ISSUED_VALUE}\n":
            issued = True
        else:
            raise RuntimeError("objective issuance marker is malformed")

        state = self._exec(
            target,
            f"if [ ! -e {shlex.quote(JOURNAL_PATH)} ]; then printf missing; "
            f"elif [ -f {shlex.quote(JOURNAL_PATH)} ]; then printf 'file\\n'; "
            f"cat {shlex.quote(JOURNAL_PATH)}; else printf invalid; fi",
        )
        if state == "missing":
            if issued:
                raise RuntimeError("objective journal is missing after issuance")
            return _empty_journal()
        if not state.startswith("file\n") or not state.removeprefix("file\n"):
            raise RuntimeError("objective journal is malformed")
        return _parse_journal(state.removeprefix("file\n"))

    def _write_journal(
        self, target: VulboxTarget, journal: Mapping[str, Any]
    ) -> None:
        encoded = _b64(json.dumps(journal, sort_keys=True, separators=(",", ":")))
        directory = shlex.quote(PRIVATE_DIR)
        temporary = shlex.quote(JOURNAL_PATH + ".next")
        path = shlex.quote(JOURNAL_PATH)
        self._exec(
            target,
            "set -eu; "
            f"install -d -o root -g root -m 0700 {directory}; umask 077; "
            f"printf %s {shlex.quote(encoded)} | base64 -d > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {path}",
        )

    def _mark_issued(self, target: VulboxTarget) -> None:
        temporary = shlex.quote(ISSUED_PATH + ".next")
        path = shlex.quote(ISSUED_PATH)
        self._exec(
            target,
            "set -eu; umask 077; "
            f"printf '%s\\n' {shlex.quote(ISSUED_VALUE)} > {temporary}; "
            f"chmod 0600 {temporary}; mv -f {temporary} {path}",
        )

    def _link_objective(
        self, target: VulboxTarget, generation: Mapping[str, Any]
    ) -> None:
        self._exec(
            target,
            "/arena/facility.py link-objective "
            + shlex.quote(str(generation["target"]))
            + " "
            + shlex.quote(str(generation["audit"])),
        )

    def _unlink_objective(
        self, target: VulboxTarget, generation: Mapping[str, Any]
    ) -> None:
        self._exec(
            target,
            "/arena/facility.py unlink-objective "
            + shlex.quote(str(generation["audit"])),
        )

    def provision_principals(
        self, target: VulboxTarget, seeds: Mapping[str, str]
    ) -> Mapping[str, BaselinePrincipal]:
        principals: dict[str, BaselinePrincipal] = {}
        users: list[dict[str, object]] = []
        jobs: list[tuple[str, str, str]] = []
        ordinary: set[str] = set()
        for attacker, seed in sorted(seeds.items()):
            username, password = principal_credentials(seed)
            job = principal_job(seed)
            if job in POOL_NAMES:
                raise RuntimeError("Jenkins principal job collision")
            users.append(
                {"username": username, "password": password, "guarded": False}
            )
            jobs.append((job, username, password))
            ordinary.add(username)
            principals[attacker] = BaselinePrincipal(
                principal_id=username,
                credentials={
                    "username": username,
                    "password": password,
                    "job": job,
                },
            )
        team_id = self._team_id(target)
        for username, password in checker_principals(team_id):
            users.append(
                {"username": username, "password": password, "guarded": True}
            )
        usernames = [str(user["username"]) for user in users]
        if len(usernames) != len(set(usernames)):
            raise RuntimeError("Jenkins principal identity collision")
        job_names = [name for name, _, _ in jobs]
        if len(job_names) != len(set(job_names)):
            raise RuntimeError("Jenkins principal job collision")
        payload = json.dumps(
            {"users": users, "ordinary": sorted(ordinary)},
            sort_keys=True,
            separators=(",", ":"),
        )
        output = self._exec(
            target, f"/arena/facility.py principals {shlex.quote(_b64(payload))}"
        )
        try:
            result = json.loads(output.strip())
            if result != {"ordinary": len(ordinary), "users": len(users)}:
                raise ValueError
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("Jenkins principal provisioning failed") from error

        guarded = self._guarded_client(target)
        if guarded.delete_job("archive-lab") not in (200, 302, 404):
            raise RuntimeError("legacy Jenkins job cleanup failed")
        status, _ = guarded.job_config("archive-lab")
        if status != 404:
            raise RuntimeError("legacy Jenkins job remains")
        assignments: list[tuple[str, str, int]] = []
        for job, username, password in jobs:
            body = checker_job_xml(
                "Managed build " + job.removeprefix("build-")[:20],
                username,
                allow_configure=True,
            )
            status, _ = guarded.job_config(job)
            if status == 404:
                status = guarded.create_job(job, body)
            elif status == 200:
                status = guarded.configure_job(job, body)
            if status not in (200, 201, 302):
                raise RuntimeError("Jenkins principal job provisioning failed")
            status, observed = guarded.job_config(job)
            if status != 200 or get_description(observed) != (
                "Managed build " + job.removeprefix("build-")[:20]
            ):
                raise RuntimeError("Jenkins principal job verification failed")
            seed_build = _seed_participant_build(
                JenkinsClient(
                    f"http://{target.host}:{target.ports['web']}",
                    username,
                    password,
                ),
                job,
            )
            assignments.append((username, job, seed_build))
        inventory_job = participant_inventory_job(team_id)
        status, inventory_config = guarded.job_config(inventory_job)
        inventory_description = participant_inventory_description(
            team_id, assignments
        )
        if status != 200 or guarded.configure_job(
            inventory_job,
            set_description(inventory_config, inventory_description),
        ) not in (200, 302):
            raise RuntimeError("participant assignment inventory provisioning failed")
        status, observed = guarded.job_config(inventory_job)
        if status != 200 or get_description(observed) != inventory_description:
            raise RuntimeError("participant assignment inventory verification failed")
        return principals

    def _restore_target(
        self,
        target: VulboxTarget,
        client: JenkinsClient,
        generation: Mapping[str, Any],
    ) -> None:
        name = str(generation["target"])
        body = protected_job_xml(pool_cover(int(generation["slot"])))
        status, _ = client.job_config(name)
        if status == 404:
            status = client.create_job(name, body)
        elif status == 200:
            status = client.configure_job(name, body)
        if status not in (200, 201, 302):
            raise RuntimeError("Jenkins objective cleanup failed")
        self._unlink_objective(target, generation)

    def _converge_target(
        self,
        target: VulboxTarget,
        client: JenkinsClient,
        generation: Mapping[str, Any],
    ) -> None:
        name = str(generation["target"])
        description = str(generation["cover"])
        body = protected_job_xml(description)
        status, _ = client.job_config(name)
        if status == 404:
            status = client.create_job(name, body)
        elif status == 200:
            status = client.configure_job(name, body)
        if status not in (200, 201, 302):
            raise RuntimeError("Jenkins objective configuration failed")
        status, observed = client.job_config(name)
        try:
            valid = status == 200 and get_description(observed) == description
        except Exception:  # noqa: BLE001
            valid = False
        if not valid:
            raise RuntimeError("Jenkins objective verification failed")
        self._link_objective(target, generation)

    def plant(
        self, target: VulboxTarget, flags: Mapping[str, Flag]
    ) -> Mapping[str, str]:
        if set(flags) != {STORE}:
            raise ValueError(f"expected store {STORE!r}, got {sorted(flags)}")
        seed = target.meta.get("round_context_seed")
        if not isinstance(seed, str):
            raise ValueError("round context seed is unavailable")
        token = flags[STORE].value
        journal = self._load_journal(target)
        client = self._guarded_client(target)

        team_id = self._team_id(target)
        material = round_context(seed, team_id)
        context = material["context"]
        current = journal.get("current")
        if isinstance(current, dict) and current.get("context") == context:
            if current.get("token") != token:
                raise RuntimeError("round context was reused with different integrity state")
            pending = journal.get("pending")
            if isinstance(pending, dict):
                self._restore_target(target, client, pending)
                journal["pending"] = None
                self._write_journal(target, journal)
            self._converge_target(target, client, current)
            self._mark_issued(target)
            return {STORE: str(current["handle"])}

        previous = journal.get("previous")
        if isinstance(previous, dict):
            self._restore_target(target, client, previous)
            journal["previous"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if isinstance(pending, dict) and (
            pending.get("context") != context or pending.get("token") != token
        ):
            self._restore_target(target, client, pending)
            journal["pending"] = None
            self._write_journal(target, journal)

        pending = journal.get("pending")
        if not isinstance(pending, dict):
            excluded = {
                str(generation["target"])
                for generation in (journal.get("current"), journal.get("previous"))
                if isinstance(generation, dict)
            }
            material = round_context(seed, team_id, excluded)
            pending = {**material, "token": token}
            pending["handle"] = pack_handle(
                {
                    key: pending[key]
                    for key in (
                        "anchor",
                        "audit",
                        "context",
                        "region",
                        "slot",
                        "target",
                        "token",
                    )
                }
                | {"store": STORE}
            )
            journal["pending"] = pending
            self._write_journal(target, journal)

        self._converge_target(target, client, pending)
        journal = {
            "v": 1,
            "current": pending,
            "previous": current,
            "pending": None,
        }
        self._write_journal(target, journal)
        self._mark_issued(target)
        return {STORE: str(pending["handle"])}

    @staticmethod
    def _anchor_observation(
        target: VulboxTarget, payload: Mapping[str, object], expected: str
    ) -> FlagObservation:
        result = read_authoritative_state(target, ANCHOR_REGION)
        if result.status is not StateReadStatus.OK:
            return FlagObservation(
                ObservationStatus.ERROR, detail=result.detail or "anchor unreadable"
            )
        raw = next(
            (
                content
                for name, content in result.files.items()
                if name == "objective-journal.json"
                or name.endswith("/objective-journal.json")
            ),
            None,
        )
        if raw is None:
            return FlagObservation(ObservationStatus.NOT_FOUND, detail="anchor missing")
        try:
            journal = _parse_journal(raw.decode())
        except (UnicodeDecodeError, RuntimeError):
            return FlagObservation(ObservationStatus.MISMATCH, detail="anchor malformed")
        found = any(
            isinstance(generation, dict)
            and generation.get("token") == expected
            and generation.get("target") == payload.get("target")
            and generation.get("anchor") == payload.get("anchor")
            and generation.get("handle") == pack_handle(dict(payload))
            for generation in (
                journal.get("current"),
                journal.get("previous"),
                journal.get("pending"),
            )
        )
        if not found:
            return FlagObservation(ObservationStatus.MISMATCH, detail="anchor mismatch")
        return FlagObservation(ObservationStatus.PRESENT, value=expected)

    @staticmethod
    def _target_observation(
        target: VulboxTarget, payload: Mapping[str, object], expected: str
    ) -> FlagObservation:
        result = read_authoritative_state(target, OBJECTIVE_REGION)
        if result.status is not StateReadStatus.OK:
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=result.detail or "objective config unreadable",
            )
        audit = str(payload["audit"])
        matches = [
            content
            for name, content in result.files.items()
            if name == audit or name.endswith("/" + audit)
        ]
        if len(matches) != 1:
            return FlagObservation(
                ObservationStatus.ERROR if len(matches) > 1 else ObservationStatus.NOT_FOUND,
                detail="objective config is ambiguous" if matches else "objective config missing",
            )
        if expected.encode() in matches[0]:
            return FlagObservation(ObservationStatus.PRESENT, value=expected)
        return FlagObservation(ObservationStatus.NOT_FOUND, detail="not in objective config")

    def retrieve(
        self, target: VulboxTarget, handle: str, expected: str | None = None
    ) -> FlagObservation:
        try:
            payload = unpack_handle(handle)
            if payload is None:
                return FlagObservation(ObservationStatus.ERROR, detail="invalid handle")
            token = payload["token"]
            if not isinstance(expected, str) or not expected:
                return FlagObservation(ObservationStatus.ERROR, detail="missing expectation")
            if expected == token:
                return self._anchor_observation(target, payload, expected)
            return self._target_observation(target, payload, expected)
        except Exception as error:  # noqa: BLE001 — observations fail closed
            return FlagObservation(
                ObservationStatus.ERROR,
                detail=f"Jenkins objective observation failed: {type(error).__name__}",
            )

    def flag_id(self, handle: str) -> str | None:
        return public_locator(handle)
