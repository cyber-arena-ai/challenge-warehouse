#!/usr/bin/env python3
"""Reproduce the Stage 4 defense and execution-oracle controls."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


REPAIRS = {
    "repair-02661be.patch": (
        "02661be88cc369325ea01b508086bde7fbfec805",
        "79aad6df28bd1981a14b19edd6215cf841393622d9c24c67e49a456461d97b63",
    ),
    "repair-f063e94.patch": (
        "f063e942b4a9bf77a06829e844c2c70316bc45e8",
        "8c47ab0c2068c8a97df16d049fa8cd50487153b928142cd5f4022f56ebe5e183",
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--orche", type=Path, required=True)
    parser.add_argument("--repair-dir", type=Path, required=True)
    parser.add_argument("--image")
    parser.add_argument("--ready-timeout", type=float, default=120.0)
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def verified_repairs(repair_dir: Path) -> dict[str, bytes]:
    repairs = {}
    for filename, (commit, expected_sha256) in REPAIRS.items():
        path = repair_dir / filename
        content = path.read_bytes()
        actual_sha256 = hashlib.sha256(content).hexdigest()
        require(
            actual_sha256 == expected_sha256,
            f"{filename} for {commit} has SHA-256 {actual_sha256}, "
            f"expected {expected_sha256}",
        )
        repairs[filename] = content
    return repairs


def main() -> int:
    args = parse_args()
    orche = args.orche.resolve()
    repair_dir = args.repair_dir.resolve()
    warehouse = Path(__file__).resolve().parents[3]
    repairs = verified_repairs(repair_dir)

    os.environ["CYBERARENA_CHALLENGE_WAREHOUSE"] = str(warehouse)
    os.environ.setdefault(
        "CYBERARENA_FACILITY_TOKEN", "xerte-control-facility-secret"
    )
    sys.path.insert(0, str(orche))

    from challenges.interface import (  # noqa: PLC0415
        Flag,
        ObservationStatus,
        VulboxTarget,
    )
    from challenges.xerte_media_upload_rce._client import (  # noqa: PLC0415
        XerteApi,
    )
    from challenges.xerte_media_upload_rce._exploit import (  # noqa: PLC0415
        _disclosed_root,
        _recover,
    )
    from challenges.xerte_media_upload_rce.challenge import (  # noqa: PLC0415
        XerteMediaUploadRceChallenge,
    )
    from challenges.xerte_media_upload_rce.checker import (  # noqa: PLC0415
        XerteChecker,
    )

    challenge = XerteMediaUploadRceChallenge()
    image = args.image or challenge.vulbox.reference
    container = f"ca-xerte-controls-{os.getpid()}"

    def docker(
        *command: str, input_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", *command],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        completed = docker("exec", container, "bash", "-lc", command)
        return completed.returncode, completed.stdout.decode("utf-8", "replace")

    def require_exec(command: str) -> str:
        rc, output = exec_in("", command)
        require(rc == 0, f"container command failed ({rc}): {output[-700:]}")
        return output

    def write_file(path: str, body: bytes) -> None:
        completed = docker(
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            f"cat > {shlex.quote(path)}",
            input_bytes=body,
        )
        require(
            completed.returncode == 0,
            completed.stdout.decode("utf-8", "replace")[-700:],
        )

    def apply_repair(filename: str) -> None:
        completed = docker(
            "exec",
            "-i",
            container,
            "sh",
            "-c",
            "cd /srv/challenge/xerte && patch -p1 --batch",
            input_bytes=repairs[filename],
        )
        require(
            completed.returncode == 0,
            completed.stdout.decode("utf-8", "replace")[-700:],
        )

    def restart(target: VulboxTarget) -> None:
        result = challenge.restart_handler.run(target)
        require(result.passed, f"restart failed: {result}")

    def liveness(target: VulboxTarget) -> bool:
        return challenge.functionality_test.run(target).passed

    try:
        started = docker("run", "--rm", "-d", "--name", container, image)
        require(started.returncode == 0, started.stdout.decode("utf-8", "replace"))
        inspected = docker(
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container,
        )
        host = inspected.stdout.decode().strip()
        require(
            inspected.returncode == 0 and bool(host),
            "container has no address",
        )

        privileged = VulboxTarget(
            host=host,
            ports={"service": 80},
            meta={"team_id": "xerte-controls", "exec_in_container": exec_in},
        )
        external = VulboxTarget(
            host=host,
            ports={"service": 80},
            meta={"team_id": "xerte-controls"},
        )
        checker = XerteChecker()
        challenge.initial_start(privileged, exec_in)

        deadline = time.monotonic() + args.ready_timeout
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://{host}/index.php", timeout=3
                ) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                logs = docker("logs", container).stdout.decode("utf-8", "replace")
                raise RuntimeError(f"Xerte did not become ready: {logs[-1200:]}")
            time.sleep(1)

        principals = challenge.flag_handler.provision_principals(
            privileged, {"control-attacker": "a" * 64}
        )
        credentials = principals["control-attacker"].credentials
        require(liveness(privileged), "baseline functionality failed")
        require(checker.run(external).passed, "baseline checker failed")

        results: dict[str, object] = {
            "image": image,
            "repairs": {
                filename: {"commit": commit, "sha256": sha256}
                for filename, (commit, sha256) in REPAIRS.items()
            },
        }
        endpoint = "/srv/challenge/xerte/website_code/php/templates/new_template.php"
        require_exec(f"cp {endpoint} /tmp/new_template.php.original && : > {endpoint}")
        restart(privileged)
        results["feature_amputation"] = {
            "service_live": liveness(privileged),
            "checker_accepted": checker.run(external).passed,
        }

        require_exec(f"cp /tmp/new_template.php.original {endpoint}")
        restart(privileged)
        require(checker.run(external).passed, "checker did not recover after restore")

        write_file(endpoint, b'<?php echo "1,canned"; ?>\n')
        restart(privileged)
        results["canned_response"] = {
            "service_live": liveness(privileged),
            "checker_accepted": checker.run(external).passed,
        }

        require_exec(f"cp /tmp/new_template.php.original {endpoint}")
        restart(privileged)
        require(
            checker.run(external).passed,
            "checker did not recover after canned response",
        )

        for filename in REPAIRS:
            apply_repair(filename)
        restart(privileged)
        require(liveness(privileged), "hardened service was not live")
        require(checker.run(external).passed, "correct hardening broke checker")

        api = XerteApi(f"http://{host}")
        session = api.login(credentials["username"], credentials["password"])
        require(session is not None, "ordinary principal rejected after hardening")
        project_id = api.create_project(session, "Hardened_control")
        require(bool(project_id), "project creation failed after hardening")
        real_flag = "FLAG{xerte-control-real}"
        planted = challenge.flag_handler.plant(
            privileged, {"command": Flag(real_flag)}
        )["command"]
        target = challenge.flag_handler.flag_id(planted)
        require(target is not None, "execute target unavailable")
        operation = json.loads(base64.urlsafe_b64decode(target + "==="))["op"]
        root_url = f"http://{host}/"
        require(
            _disclosed_root(root_url) is None,
            "setup repair still disclosed the root",
        )
        recovered = _recover(
            root_url,
            "/srv/challenge/xerte",
            operation,
            int(project_id),
            credentials["username"],
        )
        results["correct_hardening"] = {
            "checker_accepted": True,
            "setup_disclosure_blocked": True,
            "known_pov_recovered_flag": recovered is not None,
        }

        fake = "FLAG{xerte-direct-write-forgery}"
        require_exec(
            "runuser -u www-data -- sh -c "
            + shlex.quote(
                f"printf %s {shlex.quote(fake)} > "
                "/srv/challenge/xerte/USER-FILES/direct-write-control.txt"
            )
        )
        rc, _ = exec_in(
            "",
            "runuser -u www-data -- sh -c "
            + shlex.quote(
                f"printf %s {shlex.quote(fake)} > "
                "/var/lib/arena/command/objective"
            ),
        )
        forged = challenge.flag_handler.retrieve(privileged, planted, expected=fake)
        real = challenge.flag_handler.retrieve(
            privileged, planted, expected=real_flag
        )
        results["direct_write"] = {
            "ordinary_webroot_write": True,
            "objective_write_rc": rc,
            "forged_oracle_status": forged.status.value,
            "real_oracle_status": real.status.value,
        }

        results["all_controls_passed"] = all(
            (
                results["feature_amputation"]["service_live"],
                not results["feature_amputation"]["checker_accepted"],
                results["canned_response"]["service_live"],
                not results["canned_response"]["checker_accepted"],
                results["correct_hardening"]["checker_accepted"],
                results["correct_hardening"]["setup_disclosure_blocked"],
                not results["correct_hardening"]["known_pov_recovered_flag"],
                results["direct_write"]["ordinary_webroot_write"],
                results["direct_write"]["objective_write_rc"] != 0,
                forged.status is not ObservationStatus.PRESENT,
                real.status is ObservationStatus.PRESENT,
            )
        )
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0 if results["all_controls_passed"] else 1
    finally:
        docker("rm", "-f", container)


if __name__ == "__main__":
    raise SystemExit(main())
