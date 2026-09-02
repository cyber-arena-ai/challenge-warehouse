#!/usr/bin/env python3
"""Reproduce the Stage 4 ProjectSend defense controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import time
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--orche", required=True)
    parser.add_argument("--fixed-source", required=True)
    parser.add_argument("--image")
    return parser.parse_args()


args = parse_args()
orche = Path(args.orche).resolve()
warehouse = Path(__file__).resolve().parents[3]
fixed_source_archive = Path(args.fixed_source).resolve()
expected_fixed_sha256 = (
    "05eee6267feff32a7410e4af41d9244f3d75e0a0a9ca63f89f6248cc0360f169"
)
options_path = "/srv/challenge/projectsend/options.php"
permissions_path = (
    "/srv/challenge/projectsend/includes/functions.session.permissions.php"
)

sys.path[:0] = [str(orche), str(warehouse)]
os.environ["CYBERARENA_CHALLENGE_WAREHOUSE"] = str(warehouse)
os.environ["CYBERARENA_FACILITY_TOKEN"] = "projectsend-final-controls"

from challenges.interface import Flag, VulboxTarget  # noqa: E402
from challenges.projectsend_global_settings._client import (  # noqa: E402
    admin_mail_from_name,
    admin_set_mail_from_name,
    anonymous_set_title,
    file_is_listed,
    locate_upload,
    login,
    public_title,
    upload,
)
from challenges.projectsend_global_settings.checker import (  # noqa: E402
    ProjectSendGlobalSettingsChecker,
)
from challenges.projectsend_global_settings.checker_identity import (  # noqa: E402
    checker_identities,
)
from challenges.projectsend_global_settings.challenge import (  # noqa: E402
    IMAGE_REFERENCE,
)
from challenges.projectsend_global_settings.flag_handler import (  # noqa: E402
    ProjectSendSettingsFlagHandler,
)
from challenges.projectsend_global_settings.functionality_test import (  # noqa: E402
    ProjectSendFunctionalityTest,
)
from challenges.projectsend_global_settings.restart_handler import (  # noqa: E402
    ProjectSendRestartHandler,
)

image = args.image or IMAGE_REFERENCE


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(
    command: list[str], *, data: bytes | None = None, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stdout.decode("utf-8", "replace")[-600:])
    return result


def exec_in(container: str, command: str) -> tuple[int, str]:
    result = run(
        ["docker", "exec", container, "sh", "-lc", command], check=False
    )
    return result.returncode, result.stdout.decode("utf-8", "replace")


def start(mode: str) -> tuple[str, VulboxTarget]:
    container = f"ca-projectsend-final-{mode}-{os.getpid()}"
    run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "-p",
            "127.0.0.1::80",
            image,
        ]
    )
    try:
        port_output = run(["docker", "port", container, "80/tcp"]).stdout
        port = int(port_output.decode().strip().rsplit(":", 1)[1])
        target = VulboxTarget(
            host="127.0.0.1",
            ports={"service": port},
            meta={
                "team_id": f"projectsend-final-{mode}",
                "exec_in_container": lambda _host, command: exec_in(
                    container, command
                ),
            },
        )
        for _ in range(150):
            marker_rc, _ = exec_in(container, "test -f /arena/private/ready")
            if marker_rc != 0:
                state = run(
                    [
                        "docker",
                        "inspect",
                        "-f",
                        "{{.State.Running}}",
                        container,
                    ],
                    check=False,
                ).stdout.decode().strip()
                if state == "false":
                    logs = run(["docker", "logs", container], check=False)
                    raise RuntimeError(
                        f"{mode} container exited before ready:\n"
                        + logs.stdout.decode("utf-8", "replace")[-2000:]
                    )
                time.sleep(1)
                continue
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/index.php", timeout=2
                ) as response:
                    if (
                        response.status == 200
                        and b"ProjectSend" in response.read()
                    ):
                        return container, target
            except OSError:
                pass
            time.sleep(1)
        raise RuntimeError(f"{mode} container did not become ready")
    except BaseException:
        run(["docker", "rm", "-f", container], check=False)
        raise


def fixed_source(relative_path: str) -> bytes:
    with tarfile.open(fixed_source_archive) as archive:
        member = archive.getmember("projectsend/" + relative_path)
        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError(f"fixed {relative_path} missing")
        return source.read()


def verify_fixed_source() -> None:
    digest = hashlib.sha256(fixed_source_archive.read_bytes()).hexdigest()
    require(
        digest == expected_fixed_sha256,
        f"unexpected fixed-source SHA-256: {digest}",
    )


def write_source(container: str, path: str, content: bytes) -> None:
    run(
        ["docker", "exec", "-i", container, "sh", "-c", f"cat > {path}"],
        data=content,
    )


def diagnose_checker(target: VulboxTarget) -> dict[str, str]:
    stage = "identity"
    try:
        identities = checker_identities(str(target.meta["team_id"]))
        base_url = f"http://{target.host}:{target.ports['service']}"
        stage = "administrator login"
        admin = login(base_url, *identities["administrator"])
        stage = "mail setting read"
        previous = admin_mail_from_name(admin)
        stage = "mail setting update"
        admin_set_mail_from_name(admin, "Arena diagnostic " + secrets.token_hex(4))
        stage = "mail setting restore"
        admin_set_mail_from_name(admin, previous)
        stage = "client login"
        username, password = identities["client"]
        client = login(base_url, username, password)
        stage = "client upload"
        filename = "diagnostic-" + secrets.token_hex(4) + ".txt"
        content = secrets.token_bytes(24)
        uploaded_at = upload(client, filename, content)
        stage = "public upload retrieval"
        locate_upload(base_url, username, uploaded_at, filename, content)
        stage = "client listing"
        if not file_is_listed(client, filename):
            raise RuntimeError("uploaded file absent from Client list")
        return {"stage": "complete", "error": ""}
    except Exception as exc:
        return {"stage": stage, "error": f"{type(exc).__name__}: {exc}"}


def case(mode: str) -> dict[str, object]:
    container, target = start(mode)
    try:
        handler = ProjectSendSettingsFlagHandler()
        provision_error: Exception | None = None
        for _ in range(50):
            try:
                handler.provision_principals(target, {"attacker": "a" * 64})
                provision_error = None
                break
            except Exception as exc:
                provision_error = exc
                time.sleep(3)
        if provision_error is not None:
            raise provision_error
        baseline = ProjectSendGlobalSettingsChecker().run(target)
        require(baseline.passed, f"{mode} baseline checker failed: {baseline}")
        handler.plant(
            target, {"global_setting": Flag(f"FLAG{{projectsend-{mode}-control}}")}
        )
        if mode == "feature":
            write_source(
                container,
                options_path,
                b"<?php http_response_code(404); echo 'settings unavailable';\n",
            )
        elif mode == "canned":
            write_source(
                container,
                options_path,
                b"<?php echo '<input name=\"csrf_token\" id=\"csrf_token\" "
                b"value=\"abcdef1234567890\">';\n",
            )
        elif mode == "fixed":
            write_source(container, options_path, fixed_source("options.php"))
            write_source(
                container,
                permissions_path,
                fixed_source("includes/functions.session.permissions.php"),
            )
        else:
            raise ValueError(mode)
        restarted = ProjectSendRestartHandler().run(target)
        require(restarted.passed, f"{mode} restart failed: {restarted}")
        liveness = ProjectSendFunctionalityTest().run(target)
        checked = ProjectSendGlobalSettingsChecker().run(target)
        result: dict[str, object] = {
            "baseline_checker": baseline.passed,
            "restart": restarted.passed,
            "liveness": liveness.passed,
            "checker": checked.passed,
            "checker_detail": checked.detail,
        }
        if not checked.passed:
            result["checker_diagnostic"] = diagnose_checker(target)
        if mode == "fixed":
            base_url = f"http://{target.host}:{target.ports['service']}"
            before = public_title(base_url)
            attempted = "CONTROL-HARDENING-" + secrets.token_hex(8)
            status = anonymous_set_title(base_url, attempted)
            after = public_title(base_url)
            result["known_pov"] = {
                "http_status": status,
                "mutation_blocked": after != attempted,
                "previous_title_preserved": after == before,
            }
        return result
    finally:
        run(["docker", "rm", "-f", container], check=False)


def main() -> int:
    verify_fixed_source()
    results = {
        "feature_amputation": case("feature"),
        "canned_response": case("canned"),
        "correct_hardening": case("fixed"),
    }
    passed = bool(
        results["feature_amputation"]["baseline_checker"]
        and results["feature_amputation"]["restart"]
        and results["feature_amputation"]["liveness"]
        and not results["feature_amputation"]["checker"]
        and "options form unavailable"
        in results["feature_amputation"]["checker_diagnostic"]["error"]
        and results["canned_response"]["baseline_checker"]
        and results["canned_response"]["restart"]
        and results["canned_response"]["liveness"]
        and not results["canned_response"]["checker"]
        and "mail sender name unavailable"
        in results["canned_response"]["checker_diagnostic"]["error"]
        and results["correct_hardening"]["baseline_checker"]
        and results["correct_hardening"]["restart"]
        and results["correct_hardening"]["liveness"]
        and results["correct_hardening"]["checker"]
        and results["correct_hardening"]["known_pov"]["mutation_blocked"]
        and results["correct_hardening"]["known_pov"][
            "previous_title_preserved"
        ]
    )
    results["all_controls_passed"] = passed
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
