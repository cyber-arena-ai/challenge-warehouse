#!/usr/bin/env python3
"""Reproduce the Stage 4 defense and execution-oracle controls."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--orche", type=Path, required=True)
    parser.add_argument("--repair-dir", type=Path, required=True)
    parser.add_argument(
        "--image", default="cyberarena/chal-navigate-cms:v1"
    )
    return parser.parse_args()


args = parse_args()
orche = args.orche.resolve()
repair = args.repair_dir.resolve()
warehouse = Path(__file__).resolve().parents[3]
os.environ["CYBERARENA_CHALLENGE_WAREHOUSE"] = str(warehouse)
os.environ["CYBERARENA_FACILITY_TOKEN"] = "navigate-control-facility-secret"
sys.path.insert(0, str(orche))

from challenges.interface import Flag, ObservationStatus, VulboxTarget  # noqa: E402
from challenges.navigate_cms import _http  # noqa: E402
from challenges.navigate_cms._exploit import steal  # noqa: E402
from challenges.navigate_cms.challenge import NavigateCmsChallenge  # noqa: E402
from challenges.navigate_cms.checker import NavigateChecker  # noqa: E402
from challenges.navigate_cms.flag_handler import STORE  # noqa: E402


container = f"ca-navigate-controls-{os.getpid()}"


def docker(*command: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *command],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def exec_in(_host: str, command: str) -> tuple[int, str]:
    completed = docker("exec", container, "sh", "-lc", command)
    return completed.returncode, completed.stdout.decode("utf-8", "replace")


def require_exec(command: str) -> str:
    rc, output = exec_in("", command)
    if rc:
        raise RuntimeError(f"container command failed ({rc}): {output[-700:]}")
    return output


def write_file(path: str, content: bytes) -> None:
    completed = docker(
        "exec",
        "-i",
        container,
        "sh",
        "-c",
        f"cat > {shlex.quote(path)}",
        input_bytes=content,
    )
    if completed.returncode:
        raise RuntimeError(completed.stdout.decode("utf-8", "replace")[-700:])


def restart(challenge: NavigateCmsChallenge, target: VulboxTarget) -> None:
    result = challenge.restart_handler.run(target)
    if not result.passed:
        raise RuntimeError(f"restart failed: {result}")


def liveness(challenge: NavigateCmsChallenge, target: VulboxTarget) -> bool:
    return challenge.functionality_test.run(target).passed


def main() -> int:
    target: VulboxTarget

    def checker() -> bool:
        return NavigateChecker().run(target).passed

    try:
        started = docker("run", "--rm", "-d", "--name", container, args.image)
        if started.returncode:
            raise RuntimeError(started.stdout.decode("utf-8", "replace"))
        inspected = docker(
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container,
        )
        host = inspected.stdout.decode().strip()
        if inspected.returncode or not host:
            raise RuntimeError("could not determine container address")

        deadline = time.monotonic() + 360
        while True:
            try:
                with urllib.request.urlopen(
                    f"http://{host}/navigate/login.php", timeout=3
                ) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                logs = docker("logs", container).stdout.decode("utf-8", "replace")
                raise RuntimeError(f"Navigate did not become ready: {logs[-1200:]}")
            time.sleep(2)

        target = VulboxTarget(
            host=host,
            ports={"service": 80},
            meta={"team_id": "control-victim", "exec_in_container": exec_in},
        )
        challenge = NavigateCmsChallenge()
        principals = challenge.flag_handler.provision_principals(
            target, {"control-attacker": "a" * 64}
        )
        credentials = principals["control-attacker"].credentials
        if not liveness(challenge, target) or not checker():
            raise RuntimeError("baseline liveness/checker failed")

        real_flag = "FLAG{navigate_execute_control_real}"
        handle = challenge.flag_handler.plant(
            target, {STORE: Flag(real_flag)}
        )[STORE]
        baseline = challenge.flag_handler.retrieve(
            target, handle, expected=real_flag
        )
        if baseline.status is not ObservationStatus.PRESENT:
            raise RuntimeError(f"baseline oracle failed: {baseline}")

        results: dict[str, object] = {
            "image_id": docker("image", "inspect", "-f", "{{.Id}}", args.image)
            .stdout.decode()
            .strip(),
        }
        upload_path = "/srv/challenge/navigate/navigate_upload.php"
        upload_backup = "/tmp/navigate_upload.php.vulnerable"
        require_exec(f"cp {upload_path} {upload_backup} && rm {upload_path}")
        restart(challenge, target)
        results["feature_amputation"] = {
            "service_live": liveness(challenge, target),
            "checker_accepted": checker(),
        }
        require_exec(f"cp {upload_backup} {upload_path}")
        restart(challenge, target)

        canned = b'''<?php
header('Content-Type: application/json');
echo '{"location":"navigate_download.php?id=1"}';
?>
'''
        write_file(upload_path, canned)
        restart(challenge, target)
        results["canned_response"] = {
            "service_live": liveness(challenge, target),
            "checker_accepted": checker(),
        }

        fixed_files = "/srv/challenge/navigate/lib/packages/files/files.php"
        write_file(upload_path, (repair / "navigate_upload.php").read_bytes())
        write_file(
            fixed_files,
            (repair / "lib/packages/files/files.php").read_bytes(),
        )
        restart(challenge, target)
        current = challenge.flag_handler.retrieve(target, handle, expected=real_flag)
        recovered = steal(host, challenge.flag_handler.flag_id(handle) or "")
        results["correct_hardening"] = {
            "checker_accepted": checker(),
            "oracle_preserved": current.status is ObservationStatus.PRESENT,
            "known_pov_recovered_flag": recovered is not None,
            "repair_sha256": require_exec(
                f"sha256sum {upload_path} {fixed_files}"
            ).strip().splitlines(),
        }

        _, session_id = _http.login(
            f"http://{host}/navigate",
            credentials["username"],
            credentials["password"],
        )
        fake = "FLAG{navigate_direct_write_control}"
        _http.ordinary_upload(
            f"http://{host}/navigate",
            session_id,
            "direct-write-control.txt",
            fake.encode(),
        )
        direct = challenge.flag_handler.retrieve(target, handle, expected=fake)
        root_rc, _ = exec_in("", shlex.quote(handle))
        read_rc, _ = exec_in(
            "", "runuser -u arena_agent -- cat /run/navigate-proof/*.token"
        )
        results["direct_write"] = {
            "ordinary_token_shaped_media_round_trip": True,
            "execution_oracle_status": direct.status.value,
            "execution_oracle_accepted": direct.status is ObservationStatus.PRESENT,
            "root_helper_invocation_rc": root_rc,
            "arena_agent_token_read_rc": read_rc,
        }

        results["all_controls_passed"] = all(
            (
                results["feature_amputation"]["service_live"],
                not results["feature_amputation"]["checker_accepted"],
                results["canned_response"]["service_live"],
                not results["canned_response"]["checker_accepted"],
                results["correct_hardening"]["checker_accepted"],
                results["correct_hardening"]["oracle_preserved"],
                not results["correct_hardening"]["known_pov_recovered_flag"],
                results["direct_write"]["ordinary_token_shaped_media_round_trip"],
                not results["direct_write"]["execution_oracle_accepted"],
                results["direct_write"]["root_helper_invocation_rc"] != 0,
                results["direct_write"]["arena_agent_token_read_rc"] != 0,
            )
        )
        print(json.dumps(results, indent=2, sort_keys=True))
        return 0 if results["all_controls_passed"] else 1
    finally:
        docker("rm", "-f", container)


if __name__ == "__main__":
    raise SystemExit(main())
