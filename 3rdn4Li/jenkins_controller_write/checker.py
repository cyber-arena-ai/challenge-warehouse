"""External Jenkins workflow and authorization checker."""

from __future__ import annotations

import base64
import json
import secrets
import shlex
import string
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import TypedDict

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    JenkinsClient,
    checker_job_xml,
    get_description,
    get_script,
    protected_job_xml,
    set_description,
    set_script,
)
from ._ids import (
    POOL_NAMES,
    checker_pool_names,
    checker_job_name,
    checker_principals,
    participant_assignments,
    participant_inventory_job,
    principal_password,
)


_LOCKS: dict[tuple[str, str, int], threading.Lock] = {}


class _Recovery(TypedDict):
    jobs: set[str]
    configs: dict[str, tuple[str, str]]


_RECOVERY: dict[tuple[str, str, int], _Recovery] = {}
_LOCKS_GUARD = threading.Lock()
BUILD_TIMEOUT = 90
REQUIRED_JOB_PERMISSIONS = frozenset(
    {
        "Build",
        "Configure",
        "Read",
        "Workspace",
    }
)


def _archive_payload() -> str:
    """A fresh random value shaped like the scored mark, `MARK{[A-Z0-9]{32}}`."""
    alphabet = string.ascii_uppercase + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"MARK{{{body}}}"


def _same_xml(left: bytes, right: bytes) -> bool:
    try:
        return ET.canonicalize(left, strip_text=True) == ET.canonicalize(
            right, strip_text=True
        )
    except ET.ParseError:
        return False


def _description(raw: bytes) -> str:
    return get_description(raw) or ""


def _lock(team_id: str, host: str, port: int) -> threading.Lock:
    key = (team_id, host, port)
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _recovery(team_id: str, host: str, port: int) -> _Recovery:
    key = (team_id, host, port)
    with _LOCKS_GUARD:
        return _RECOVERY.setdefault(
            key,
            {
                "jobs": set(),
                "configs": {},
            },
        )


class JenkinsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "jenkins-controller-write-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("web",)

    def run(self, target: VulboxTarget) -> CheckResult:
        try:
            team_id = str(target.meta["team_id"])
            port = target.ports["web"]
            guarded_credentials = secrets.choice(checker_principals(team_id))
        except (KeyError, TypeError, ValueError, RuntimeError):
            return CheckResult("checker", False, "checker accounts unavailable")
        base = f"http://{target.host}:{port}"
        guarded = JenkinsClient(base, *guarded_credentials)
        with _lock(team_id, target.host, port):
            return self._run_serialized(
                team_id,
                base,
                guarded,
                _recovery(team_id, target.host, port),
                target.meta.get("exec_stdin"),
            )

    @staticmethod
    def _jobs(client: JenkinsClient) -> list[str]:
        status, document = client.json("/api/json?tree=jobs[name]")
        if status != 200 or not isinstance(document, dict):
            raise RuntimeError("Jenkins job listing failed")
        rows = document.get("jobs")
        if not isinstance(rows, list):
            raise RuntimeError("Jenkins job listing was malformed")
        names = [
            row.get("name") for row in rows if isinstance(row, dict)
        ]
        if any(not isinstance(name, str) for name in names):
            raise RuntimeError("Jenkins job identity was malformed")
        return names

    @staticmethod
    def _valid_participant_config(raw: bytes, username: str) -> bool:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return False
        permissions = {
            element.text
            for element in root.findall(
                "./properties/hudson.security.AuthorizationMatrixProperty/permission"
            )
            if element.text
        }
        required = {
            f"hudson.model.Item.{permission}:{username}"
            for permission in REQUIRED_JOB_PERMISSIONS
        }
        parameter_names = {
            element.text
            for element in root.findall(
                "./properties/hudson.model.ParametersDefinitionProperty/"
                "parameterDefinitions/*/name"
            )
            if element.text
        }
        quiet_period = root.findtext("./quietPeriod")
        try:
            quiet_period_ok = quiet_period is None or 0 <= int(quiet_period) <= 5
        except ValueError:
            quiet_period_ok = False
        return (
            root.tag == "flow-definition"
            and root.findtext("./disabled") == "false"
            and get_script(raw) is not None
            and required.issubset(permissions)
            and "TOKEN" in parameter_names
            and quiet_period_ok
        )

    @classmethod
    def _replay_queue_ids(
        cls, guarded: JenkinsClient, name: str, script: str
    ) -> tuple[int, ...] | None:
        encoded_name = base64.b64encode(name.encode()).decode()
        encoded_script = base64.b64encode(script.encode()).decode()
        status, raw = guarded.run_script(
            "import groovy.json.JsonOutput\n"
            "import jenkins.model.Jenkins\n"
            f"def expectedJob = new String('{encoded_name}'.decodeBase64(), "
            "'UTF-8')\n"
            f"def expectedScript = new String('{encoded_script}'.decodeBase64(), "
            "'UTF-8')\n"
            "def ids = []\n"
            "Jenkins.get().getQueue().getItems().each { item ->\n"
            "  if (item.task.fullName == expectedJob) {\n"
            "    item.getAllActions().each { action ->\n"
            "      if (action.class.name == "
            "'org.jenkinsci.plugins.workflow.cps.replay.ReplayFlowFactoryAction') "
            "{\n"
            "        def field = action.class.getDeclaredField("
            "'replacementMainScript')\n"
            "        field.setAccessible(true)\n"
            "        if (field.get(action) == expectedScript) { ids << item.id }\n"
            "      }\n"
            "    }\n"
            "  }\n"
            "}\n"
            "println(JsonOutput.toJson(ids))"
        )
        if status in (401, 403, 404):
            return None
        try:
            rows = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if (
            status != 200
            or not isinstance(rows, list)
            or any(
                not isinstance(item_id, int) or isinstance(item_id, bool)
                for item_id in rows
            )
            or len(rows) != len(set(rows))
        ):
            return None
        return tuple(rows)

    @classmethod
    def _cleanup_assigned_build(
        cls,
        name: str,
        first_candidate: int,
        token: str,
        script: str,
        queue_id: int | None,
        replay_build: int | None,
        guarded: JenkinsClient,
    ) -> None:
        quoted = urllib.parse.quote(name)
        if replay_build is None:
            status, state = cls._job_status(guarded, name)
            if status == 404:
                return
            if status != 200 or not isinstance(state, dict):
                raise RuntimeError("participant Pipeline build cleanup failed")
            builds = state.get("builds")
            if not isinstance(builds, list):
                raise RuntimeError("participant Pipeline build cleanup failed")
            exact = [
                build.get("number")
                for build in builds
                if isinstance(build, dict)
                and isinstance(build.get("number"), int)
                and not isinstance(build.get("number"), bool)
                and build["number"] >= first_candidate
                and build.get("description") == token
            ]
            if len(exact) > 1:
                raise RuntimeError("participant Pipeline build cleanup is ambiguous")
            if exact:
                replay_build = exact[0]
            elif queue_id is None:
                queue_ids = cls._replay_queue_ids(guarded, name, script)
                if queue_ids is None:
                    raise RuntimeError("participant Pipeline queue cleanup failed")
                if len(queue_ids) > 1:
                    raise RuntimeError(
                        "participant Pipeline queue cleanup is ambiguous"
                    )
                if queue_ids:
                    queue_id = queue_ids[0]

        if replay_build is None and queue_id is not None:
            cancelled, _ = guarded.request(
                "/queue/cancelItem?" + urllib.parse.urlencode({"id": queue_id}),
                data=b"",
                headers=guarded.crumb,
            )
            if cancelled not in (200, 204, 302, 404):
                raise RuntimeError("participant Pipeline queue cleanup failed")
            deadline = time.monotonic() + 10
            queue_missing = False
            while time.monotonic() < deadline:
                status, queue = guarded.json(
                    f"/queue/item/{queue_id}/api/json?tree="
                    "cancelled,executable[number]"
                )
                build_status, state = cls._job_status(guarded, name)
                if build_status == 404 and status == 404:
                    return
                if build_status != 200 or not isinstance(state, dict):
                    raise RuntimeError("participant Pipeline build cleanup failed")
                builds = state.get("builds")
                if not isinstance(builds, list):
                    raise RuntimeError("participant Pipeline build cleanup failed")
                exact = [
                    build.get("number")
                    for build in builds
                    if isinstance(build, dict)
                    and isinstance(build.get("number"), int)
                    and not isinstance(build.get("number"), bool)
                    and build["number"] >= first_candidate
                    and build.get("description") == token
                ]
                if len(exact) == 1:
                    replay_build = exact[0]
                    break
                if status == 404:
                    queue_missing = True
                    time.sleep(0.1)
                    continue
                queue_missing = False
                if status != 200 or not isinstance(queue, dict):
                    raise RuntimeError("participant Pipeline queue cleanup failed")
                executable = queue.get("executable")
                if isinstance(executable, dict) and isinstance(
                    executable.get("number"), int
                ):
                    replay_build = executable["number"]
                    break
                if queue.get("cancelled") is True:
                    return
                time.sleep(0.1)
            else:
                if queue_missing:
                    return
                raise RuntimeError("participant Pipeline queue cleanup timed out")

        if replay_build is None:
            return
        build_status, build = guarded.json(
            f"/job/{quoted}/{replay_build}/api/json?tree=building"
        )
        if build_status == 200 and isinstance(build, dict) and build.get(
            "building"
        ) is True:
            stopped, _ = guarded.request(
                f"/job/{quoted}/{replay_build}/stop",
                data=b"",
                headers=guarded.crumb,
            )
            if stopped not in (200, 302, 404):
                raise RuntimeError("participant Pipeline build cleanup failed")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                build_status, build = guarded.json(
                    f"/job/{quoted}/{replay_build}/api/json?tree=building"
                )
                if build_status == 404 or (
                    build_status == 200
                    and isinstance(build, dict)
                    and build.get("building") is False
                ):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("participant Pipeline build cleanup timed out")
        elif build_status != 404 and (
            build_status != 200
            or not isinstance(build, dict)
            or build.get("building") is not False
        ):
            raise RuntimeError("participant Pipeline build cleanup failed")
        deleted, _ = guarded.request(
            f"/job/{quoted}/{replay_build}/doDelete",
            data=b"",
            headers=guarded.crumb,
        )
        if deleted not in (200, 204, 302, 404):
            raise RuntimeError("participant Pipeline build cleanup failed")
        deleted_status, _ = guarded.json(
            f"/job/{quoted}/{replay_build}/api/json?tree=building"
        )
        if deleted_status != 404:
            raise RuntimeError("participant Pipeline build cleanup failed")

    @classmethod
    def _run_assigned_build(
        cls,
        name: str,
        seed_build: int,
        ordinary: JenkinsClient,
        guarded: JenkinsClient,
        exec_stdin,
    ) -> None:
        quoted = urllib.parse.quote(name)
        seed_status, seed = ordinary.json(
            f"/job/{quoted}/{seed_build}/api/json?tree=building,result"
        )
        if (
            seed_status != 200
            or not isinstance(seed, dict)
            or seed.get("building") is not False
            or seed.get("result") != "SUCCESS"
        ):
            raise RuntimeError("participant Pipeline replay seed is unavailable")
        status, state = cls._job_status(ordinary, name)
        if status != 200 or not isinstance(state, dict):
            raise RuntimeError("participant Pipeline build state is unavailable")
        first_candidate = state.get("nextBuildNumber")
        if not isinstance(first_candidate, int) or isinstance(first_candidate, bool):
            raise RuntimeError("participant Pipeline build number is malformed")
        token = secrets.token_hex(32)
        payload = _archive_payload()
        artifact = secrets.token_hex(12) + ".txt"
        link_entry = secrets.token_hex(12) + ".txt"
        target_dir = secrets.token_hex(12)
        link_dir = secrets.token_hex(12)
        script = (
            f"currentBuild.description = '{token}'\n"
            "node('untrusted') {\n"
            "    deleteDir()\n"
            f"    writeFile file: '{artifact}', text: '{payload}'\n"
            f"    sh 'mkdir {target_dir} && printf %s \"{payload}\" > "
            f"{target_dir}/value.txt && ln -s {target_dir} {link_dir} && "
            f"ln -s {link_dir}/value.txt {link_entry}'\n"
            f"    archiveArtifacts artifacts: '{artifact}', "
            "followSymlinks: true\n"
            f"    archiveArtifacts artifacts: '{link_entry},{link_dir}/**', "
            "followSymlinks: true\n"
            "}"
        )
        form = {"mainScript": script}
        queue_id: int | None = None
        replay_build: int | None = None
        submission_may_exist = False
        try:
            headers = {
                **ordinary.crumb,
                "Content-Type": "application/x-www-form-urlencoded",
            }
            submission_may_exist = True
            status, _ = ordinary.request(
                f"/job/{quoted}/{seed_build}/replay/run",
                data=urllib.parse.urlencode(
                    {"mainScript": script, "json": json.dumps(form)}
                ).encode(),
                headers=headers,
            )
            if status not in (200, 201, 302):
                submission_may_exist = False
                raise RuntimeError(
                    f"participant Pipeline replay returned HTTP {status}"
                )
            queue_ids = cls._replay_queue_ids(guarded, name, script)
            if queue_ids is not None:
                if len(queue_ids) > 1:
                    raise RuntimeError("participant Pipeline queue state is ambiguous")
                if queue_ids:
                    queue_id = queue_ids[0]
            deadline = time.monotonic() + BUILD_TIMEOUT
            while time.monotonic() < deadline:
                status, state = cls._job_status(ordinary, name)
                if status != 200 or not isinstance(state, dict):
                    raise RuntimeError("participant Pipeline build state is unavailable")
                builds = state.get("builds")
                if not isinstance(builds, list):
                    raise RuntimeError("participant Pipeline build state is malformed")
                for build in builds:
                    number = build.get("number") if isinstance(build, dict) else None
                    if (
                        not isinstance(number, int)
                        or isinstance(number, bool)
                        or number < first_candidate
                    ):
                        continue
                    if build.get("description") != token:
                        continue
                    replay_build = number
                    if build.get("building") is not False:
                        break
                    artifact_status, artifact_body = ordinary.request(
                        f"/job/{quoted}/{number}/artifact/"
                        + urllib.parse.quote(artifact)
                    )
                    link_status, link_body = ordinary.request(
                        f"/job/{quoted}/{number}/artifact/"
                        + urllib.parse.quote(f"{link_dir}/value.txt")
                    )
                    if (
                        build.get("result") != "SUCCESS"
                        or artifact_status != 200
                        or artifact_body.decode(errors="replace") != payload
                        or link_status != 200
                        or link_body.decode(errors="replace") != payload
                    ):
                        raise RuntimeError("participant Pipeline replay build failed")
                    if not cls._archived_link(
                        exec_stdin,
                        name,
                        number,
                        link_entry,
                        f"{link_dir}/value.txt",
                    ):
                        raise RuntimeError(
                            "participant Pipeline symlink artifact is unverified"
                        )
                    return
                if replay_build is not None:
                    owned = next(
                        (
                            build
                            for build in builds
                            if isinstance(build, dict)
                            and build.get("number") == replay_build
                        ),
                        None,
                    )
                    if (
                        isinstance(owned, dict)
                        and owned.get("building") is False
                        and owned.get("description") != token
                    ):
                        raise RuntimeError("participant Pipeline replay build failed")
                time.sleep(1)
            raise RuntimeError("participant Pipeline replay build timed out")
        finally:
            if submission_may_exist:
                cls._cleanup_assigned_build(
                    name,
                    first_candidate,
                    token,
                    script,
                    queue_id,
                    replay_build,
                    guarded,
                )

    @classmethod
    def _participant_assignments(
        cls, team_id: str, base: str, guarded: JenkinsClient, exec_stdin
    ) -> list[tuple[str, str, JenkinsClient]]:
        inventory_job = participant_inventory_job(team_id)
        status, inventory_config = guarded.job_config(inventory_job)
        if status != 200:
            raise RuntimeError("participant assignment inventory is unavailable")
        assignments: list[tuple[str, str, JenkinsClient]] = []
        for username, name, seed_build in participant_assignments(
            team_id, _description(inventory_config)
        ):
            ordinary = JenkinsClient(base, username, principal_password(username))
            jobs = cls._jobs(ordinary)
            if jobs != [name] or name in POOL_NAMES:
                raise RuntimeError("participant Pipeline assignment is unavailable")
            status, raw = ordinary.job_config(name)
            job_status, job = ordinary.json(
                f"/job/{urllib.parse.quote(name)}/api/json?tree=_class,buildable"
            )
            if (
                status != 200
                or not cls._valid_participant_config(raw, username)
                or job_status != 200
                or not isinstance(job, dict)
                or job.get("_class")
                != "org.jenkinsci.plugins.workflow.job.WorkflowJob"
                or job.get("buildable") is not True
            ):
                raise RuntimeError("participant Pipeline assignment is unavailable")
            cls._run_assigned_build(
                name, seed_build, ordinary, guarded, exec_stdin
            )
            assignments.append((username, name, ordinary))

        for _, name, _ in assignments:
            for _, other_name, other in assignments:
                if other_name != name and other.job_config(name)[0] not in (403, 404):
                    raise RuntimeError("participant Pipeline isolation failed")
        return assignments

    @classmethod
    def _cleanup_stale(
        cls, guarded: JenkinsClient, recovery: _Recovery
    ) -> tuple[int, int]:
        restored = 0
        for name, (original, owned) in list(recovery["configs"].items()):
            status, current = guarded.job_config(name)
            if status != 200:
                raise RuntimeError("checker configuration cleanup failed")
            current_description = _description(current)
            if current_description == owned:
                if guarded.configure_job(
                    name, set_description(current, original)
                ) not in (200, 302):
                    raise RuntimeError("checker configuration cleanup failed")
                status, observed = guarded.job_config(name)
                if status != 200 or _description(observed) != original:
                    raise RuntimeError("checker configuration remains modified")
                restored += 1
            elif current_description != original:
                # A participant superseded the checker-owned field. Do not
                # overwrite their concurrent configuration change.
                recovery["configs"].pop(name)
                continue
            recovery["configs"].pop(name)

        stale = sorted(recovery["jobs"])
        jobs_ok = True
        for name in stale:
            if guarded.delete_job(name) not in (200, 302, 404):
                jobs_ok = False
        existing = set(cls._jobs(guarded))
        remaining = set(stale) & existing
        if not jobs_ok or remaining:
            raise RuntimeError("stale checker jobs remain")
        recovery["jobs"].difference_update(stale)

        return len(stale), restored

    @staticmethod
    def _job_status(client: JenkinsClient, name: str) -> tuple[int, object]:
        return client.json(
            f"/job/{urllib.parse.quote(name)}/api/json?tree="
            "nextBuildNumber,builds["
            "number,building,result,description]"
        )

    @staticmethod
    def _archived_link(
        exec_stdin, name: str, number: int, entry: str, expected: str
    ) -> bool:
        """Whether the build archived `entry` as a symbolic link to `expected`.

        Jenkins never discloses an archived link's target over HTTP, so this
        reads it in prod through `exec_stdin`, which ships the probe from the
        poller and leaves nothing on prod disk. Extraction that drops the link,
        replaces it with an ordinary file, or rewrites its target all read as a
        target that is not `expected`."""
        path = shlex.quote(
            f"/var/jenkins_home/jobs/{name}/builds/{number}/archive/{entry}"
        )
        _rc, out, _err, _timed_out = exec_stdin(
            f"readlink -- {path} 2>/dev/null\n".encode()
        )
        return (out or "").strip() == expected

    @classmethod
    def _run_build(
        cls,
        name: str,
        ordinary: JenkinsClient,
        token: str,
    ) -> int:
        status, document = cls._job_status(ordinary, name)
        if status != 200 or not isinstance(document, dict):
            raise RuntimeError("checker build state is unavailable")
        expected = document.get("nextBuildNumber")
        if not isinstance(expected, int) or isinstance(expected, bool):
            raise RuntimeError("checker build number is malformed")
        status, _ = ordinary.request(
            f"/job/{urllib.parse.quote(name)}/buildWithParameters?"
            + urllib.parse.urlencode({"TOKEN": token}),
            data=b"",
            headers=ordinary.crumb,
        )
        if status not in (200, 201, 302):
            raise RuntimeError(f"checker build trigger returned HTTP {status}")
        deadline = time.monotonic() + BUILD_TIMEOUT
        while time.monotonic() < deadline:
            status, build = ordinary.json(
                f"/job/{urllib.parse.quote(name)}/{expected}/api/json"
            )
            if status == 200 and isinstance(build, dict):
                if build.get("building") is False:
                    if build.get("result") != "SUCCESS":
                        raise RuntimeError("checker build failed")
                    return expected
            elif status != 404:
                raise RuntimeError("checker build observation failed")
            time.sleep(1)
        raise RuntimeError("checker build timed out")

    @classmethod
    def _run_serialized(
        cls,
        team_id: str,
        base: str,
        guarded: JenkinsClient,
        recovery: _Recovery,
        exec_stdin,
    ) -> CheckResult:
        children: list[CheckResult] = []
        try:
            stale_jobs, stale_configs = cls._cleanup_stale(
                guarded, recovery
            )
            try:
                assignments = cls._participant_assignments(
                    team_id, base, guarded, exec_stdin
                )
            except RuntimeError as error:
                children.append(
                    CheckResult("participant_pipelines", False, str(error))
                )
                raise
            username, assigned_job, ordinary = secrets.choice(assignments)
            children.append(
                CheckResult(
                    "participant_pipelines",
                    True,
                    f"assignments={len(assignments)},selected={assigned_job}",
                )
            )

            status, controller = ordinary.json("/api/json?tree=numExecutors")
            controller_ok = (
                status == 200
                and isinstance(controller, dict)
                and controller.get("numExecutors") == 0
            )
            status, agent = ordinary.json(
                "/computer/untrusted-agent/api/json?tree=offline,numExecutors"
            )
            agent_ok = (
                status == 200
                and isinstance(agent, dict)
                and agent.get("offline") is False
                and isinstance(agent.get("numExecutors"), int)
                and agent["numExecutors"] >= 2
            )
            children.append(
                CheckResult(
                    "topology",
                    controller_ok and agent_ok,
                    f"controller={controller_ok},agent={agent_ok}",
                )
            )

            maintainer_name = checker_job_name(secrets.token_bytes(14))
            while maintainer_name in POOL_NAMES:
                maintainer_name = checker_job_name(secrets.token_bytes(14))
            recovery["jobs"].add(maintainer_name)
            status = guarded.create_job(
                maintainer_name,
                checker_job_xml(
                    "Managed build "
                    + maintainer_name.removeprefix("build-")[:20],
                    username,
                    allow_configure=True,
                ),
            )
            if status not in (200, 201, 302):
                raise RuntimeError("maintainer checker job creation failed")
            status, attack_config = ordinary.job_config(maintainer_name)
            attack_script = get_script(attack_config) if status == 200 else None
            token = _archive_payload()
            artifact = secrets.token_hex(12) + ".txt"
            link_entry = secrets.token_hex(12) + ".txt"
            target_dir = secrets.token_hex(12)
            link_dir = secrets.token_hex(12)
            symlink_artifact = f"{link_dir}/value.txt"
            maintainer_script = (
                "node('untrusted') {\n"
                "    deleteDir()\n"
                f"    writeFile file: '{artifact}', text: params.TOKEN\n"
                f"    sh 'mkdir {target_dir} && printf %s \"$TOKEN\" > "
                f"{target_dir}/value.txt && ln -s {target_dir} {link_dir} && "
                f"ln -s {link_dir}/value.txt {link_entry}'\n"
                f"    archiveArtifacts artifacts: '{artifact}', "
                "followSymlinks: true\n"
                f"    archiveArtifacts artifacts: '{link_entry},{link_dir}/**', "
                "followSymlinks: true\n"
                "}"
            )
            changed_attack_config = (
                set_script(attack_config, maintainer_script)
                if attack_script is not None
                else attack_config
            )
            post = (
                ordinary.configure_job(maintainer_name, changed_attack_config)
                if attack_script is not None
                else status
            )
            observed_status, observed_attack_config = ordinary.job_config(
                maintainer_name
            )
            configure_ok = (
                status == 200
                and post in (200, 302)
                and observed_status == 200
                and _same_xml(observed_attack_config, changed_attack_config)
            )
            children.append(
                CheckResult(
                    "maintainer_configure",
                    configure_ok,
                    f"read={status},post={post},reread={observed_status},"
                    "mutation=Pipeline",
                )
            )
            if not configure_ok:
                raise RuntimeError("maintainer Pipeline configuration failed")

            name = secrets.choice(
                tuple(
                    candidate
                    for candidate in checker_pool_names(team_id)
                    if candidate != participant_inventory_job(team_id)
                )
            )
            status, raw = guarded.job_config(name)
            if status != 200:
                raise RuntimeError("checker pool member is unavailable")
            original_description = _description(raw)
            changed = "Protected build configuration " + secrets.token_hex(10)
            recovery["configs"][name] = (original_description, changed)
            config_ok = (
                guarded.configure_job(name, protected_job_xml(changed))
                in (200, 302)
            )
            status, observed = guarded.job_config(name)
            config_ok = (
                config_ok and status == 200 and get_description(observed) == changed
            )
            read_denied, _ = ordinary.job_config(name)
            configure_denied = ordinary.configure_job(
                name,
                protected_job_xml("Protected build configuration " + secrets.token_hex(10)),
            )
            build_denied, _ = ordinary.request(
                f"/job/{urllib.parse.quote(name)}/build",
                data=b"",
                headers=ordinary.crumb,
            )
            config_ok = config_ok and all(
                result in (403, 404)
                for result in (read_denied, configure_denied, build_denied)
            )
            children.append(
                CheckResult(
                    "guarded_config",
                    config_ok,
                    f"roundtrip={status},ordinary="
                    f"{read_denied}/{configure_denied}/{build_denied}",
                )
            )

            number = cls._run_build(maintainer_name, ordinary, token)
            status, regular = ordinary.request(
                f"/job/{urllib.parse.quote(maintainer_name)}/{number}/artifact/"
                + urllib.parse.quote(artifact)
            )
            link_status, symlink = ordinary.request(
                f"/job/{urllib.parse.quote(maintainer_name)}/{number}/artifact/"
                + urllib.parse.quote(symlink_artifact)
            )
            entry_ok = cls._archived_link(
                exec_stdin,
                maintainer_name,
                number,
                link_entry,
                symlink_artifact,
            )
            archive_ok = (
                status == 200
                and regular.decode(errors="replace") == token
                and link_status == 200
                and symlink.decode(errors="replace") == token
                and entry_ok
            )
            children.append(
                CheckResult(
                    "archive_workflow",
                    archive_ok,
                    f"build={number},artifact={status},symlink={link_status},"
                    f"link_entry={entry_ok}",
                )
            )
        except Exception as error:  # noqa: BLE001 — checker failures are results
            children.append(
                CheckResult(
                    "checker_operation",
                    False,
                    f"{type(error).__name__}: {error}",
                )
            )
        finally:
            try:
                current_jobs, current_configs = cls._cleanup_stale(
                    guarded, recovery
                )
                children.append(
                    CheckResult(
                        "checker_cleanup",
                        True,
                        f"stale_jobs={stale_jobs if 'stale_jobs' in locals() else 0},"
                        f"stale_configs={stale_configs if 'stale_configs' in locals() else 0},"
                        f"current_jobs={current_jobs},current_configs={current_configs}",
                    )
                )
            except Exception as error:  # noqa: BLE001
                children.append(
                    CheckResult("checker_cleanup", False, type(error).__name__)
                )
        return CheckResult(
            "checker", all(child.passed for child in children), children=children
        )
