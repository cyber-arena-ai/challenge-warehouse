#!/usr/bin/env python3
"""Reproduce the Stage 4 defense and execution-oracle controls."""

from __future__ import annotations

import argparse
import json
import os
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--orche", required=True)
    parser.add_argument(
        "--image", default="cyberarena/chal-openfire-setup-execute:v1"
    )
    parser.add_argument("--expected-image-id", required=True)
    return parser.parse_args()


args = parse_args()
warehouse = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
os.environ["CYBERARENA_CHALLENGE_WAREHOUSE"] = warehouse
os.environ["CYBERARENA_FACILITY_TOKEN"] = "openfire-control-facility-secret"
sys.path.insert(0, os.path.abspath(args.orche))

import docker  # noqa: E402

from challenges.interface import ObservationStatus, VulboxTarget  # noqa: E402
from challenges.openfire_setup_execute import (  # noqa: E402
    OpenfireSetupExecuteChallenge,
)
from challenges.openfire_setup_execute._exploit import steal  # noqa: E402
from challenges.openfire_setup_execute.checker import OpenfireChecker  # noqa: E402


client = docker.from_env()
container_name = f"ca-openfire-controls-{os.getpid()}"
container = client.containers.run(
    args.image, name=container_name, detach=True
)


def execute(_host: str, command: str) -> tuple[int, str]:
    result = container.exec_run(["bash", "-lc", command])
    return result.exit_code, result.output.decode(errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def restart(challenge, target) -> None:
    result = challenge.restart_handler.run(target)
    require(result.passed, f"restart failed: {result}")


def liveness(challenge, target) -> bool:
    return challenge.functionality_test.run(target).passed


try:
    container.reload()
    image_id = container.image.id
    require(
        image_id == args.expected_image_id,
        f"unexpected image ID: {image_id}",
    )
    ip = next(iter(container.attrs["NetworkSettings"]["Networks"].values()))[
        "IPAddress"
    ]
    challenge = OpenfireSetupExecuteChallenge()
    checker = OpenfireChecker()
    privileged = VulboxTarget(
        ip,
        {"service": 9090, "xmpp": 5222},
        {"exec_in_container": execute, "team_id": "controls"},
    )
    external = VulboxTarget(
        ip, {"service": 9090, "xmpp": 5222}, {"team_id": "controls"}
    )
    challenge.initial_start(privileged, execute)
    challenge.flag_handler.provision_principals(
        privileged, {"controls-attacker": "a" * 64}
    )
    require(liveness(challenge, privileged), "baseline liveness failed")
    baseline = checker.run(external)
    require(baseline.passed, f"baseline checker failed: {baseline}")

    webroot = "/srv/challenge/openfire/xmppserver/src/main/webapp"
    plugin = f"{webroot}/plugin-admin.jsp"
    user_create = f"{webroot}/user-create.jsp"
    webxml = f"{webroot}/WEB-INF/web.xml"
    rc, output = execute(
        ip,
        f"cp {plugin} /tmp/plugin-admin.jsp.original && "
        f"cp {user_create} /tmp/user-create.jsp.original && "
        f"cp {webxml} /tmp/web.xml.original",
    )
    require(rc == 0, f"control backups failed: {output[-200:]}")

    results: dict[str, object] = {"image_id": image_id}
    rc, _ = execute(ip, f"printf '%s\n' 'plugin administration disabled' > {plugin}")
    require(rc == 0, "feature-amputation edit failed")
    restart(challenge, privileged)
    results["feature_amputation"] = {
        "service_live": liveness(challenge, privileged),
        "checker_accepted": checker.run(external).passed,
    }

    rc, _ = execute(ip, f"cp /tmp/plugin-admin.jsp.original {plugin}")
    require(rc == 0, "plugin restore failed")
    restart(challenge, privileged)
    rc, _ = execute(ip, f"printf '%s\n' 'success=true&username=fixed' > {user_create}")
    require(rc == 0, "canned-response edit failed")
    restart(challenge, privileged)
    results["canned_response"] = {
        "service_live": liveness(challenge, privileged),
        "checker_accepted": checker.run(external).passed,
    }

    rc, _ = execute(ip, f"cp /tmp/user-create.jsp.original {user_create}")
    require(rc == 0, "user-create restore failed")
    old = (
        "login.jsp,index.jsp?logout=true,setup/index.jsp,setup/setup-*,.gif,.png,"
        "error-serverdown.jsp,loginToken.jsp"
    )
    new = (
        "login.jsp,index.jsp?logout=true,setup/index.jsp,"
        "setup/setup-admin-settings.jsp,setup/setup-completed.jsp,"
        "setup/setup-datasource-jndi.jsp,setup/setup-datasource-settings.jsp,"
        "setup/setup-datasource-standard.jsp,setup/setup-finished.jsp,"
        "setup/setup-host-settings.jsp,setup/setup-ldap-group.jsp,"
        "setup/setup-ldap-server.jsp,setup/setup-ldap-user.jsp,"
        "setup/setup-profile-settings.jsp,.gif,.png,error-serverdown.jsp,"
        "loginToken.jsp"
    )
    command = (
        "python3 -c \"from pathlib import Path; "
        f"p=Path('{webxml}'); s=p.read_text(); "
        f"assert s.count('{old}') == 1; p.write_text(s.replace('{old}','{new}'))\""
    )
    rc, output = execute(ip, command)
    require(rc == 0, f"hardening edit failed: {output[-200:]}")
    restart(challenge, privileged)

    expected = "FLAG{OPENFIRE-DIRECT-WRITE-CONTROL}"
    locator = challenge.flag_handler.plant_one(privileged, expected)
    reached, recovered = steal(ip, locator)
    results["correct_hardening"] = {
        "service_live": liveness(challenge, privileged),
        "checker_accepted": checker.run(external).passed,
        "known_pov_target_reached": reached,
        "known_pov_recovered_flag": recovered is not None,
    }

    proof = f"/var/lib/openfire-arena/proofs/{locator}"
    write_rc, _ = execute(
        ip, f"runuser -u openfire -- sh -c 'printf forged > {proof}'"
    )
    read_rc, _ = execute(ip, f"runuser -u openfire -- cat {proof}")
    observation = challenge.flag_handler.retrieve(privileged, locator, expected)
    results["direct_write"] = {
        "service_write_rc": write_rc,
        "service_read_rc": read_rc,
        "execution_oracle_status": observation.status.value,
    }

    results["all_controls_passed"] = all(
        (
            results["feature_amputation"]["service_live"],
            not results["feature_amputation"]["checker_accepted"],
            results["canned_response"]["service_live"],
            not results["canned_response"]["checker_accepted"],
            results["correct_hardening"]["service_live"],
            results["correct_hardening"]["checker_accepted"],
            not results["correct_hardening"]["known_pov_target_reached"],
            not results["correct_hardening"]["known_pov_recovered_flag"],
            results["direct_write"]["service_write_rc"] != 0,
            results["direct_write"]["service_read_rc"] != 0,
            observation.status is ObservationStatus.PRESENT,
        )
    )
    print(json.dumps(results, indent=2, sort_keys=True))
    raise SystemExit(0 if results["all_controls_passed"] else 1)
finally:
    container.remove(force=True)
