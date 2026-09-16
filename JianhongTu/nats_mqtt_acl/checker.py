"""External SLA checker for the native restricted-device MQTT workflow."""

from __future__ import annotations

import secrets
import socket
import string
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._ids import (
    ISSUED_COHORT_FILE,
    client_id,
    facility_publisher,
    verified_issued_cohort,
)
from ._mqtt import MqttClient, MqttError


_PROOF_ALPHABET = string.ascii_uppercase + string.digits


def _noise_value() -> str:
    """Return fresh, non-scoring data with the same shape as a proof token."""
    body = "".join(secrets.choice(_PROOF_ALPHABET) for _ in range(32))
    return f"FLAG{{{body}}}"


def _issued_principals(target: VulboxTarget) -> tuple[tuple[str, str], ...]:
    exec_in = target.meta.get("exec_in_container")
    if not callable(exec_in):
        raise RuntimeError("issued principal cohort is unavailable")
    rc, output = exec_in(target.host, f"cat {ISSUED_COHORT_FILE}")
    if rc != 0:
        raise RuntimeError("issued principal cohort is unavailable")
    return verified_issued_cohort(output or "")


class NatsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    @staticmethod
    def _client(
        host: str, port: int, username: str, password: str
    ) -> MqttClient:
        return MqttClient(
            host,
            port,
            username,
            password,
            client_id=client_id(),
        )

    @staticmethod
    def _receive_until(
        client: MqttClient,
        topic: str,
        payload: bytes,
        timeout: float = 5,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                found_topic, found_payload, retained = client.receive(
                    timeout=max(0.1, deadline - time.monotonic())
                )
            except socket.timeout:
                return False
            if found_topic == topic and found_payload == payload and retained:
                return True
        return False

    def run(self, target: VulboxTarget) -> CheckResult:
        host = target.host
        port = target.ports["service"]
        report = secrets.token_hex(12)
        public_value = _noise_value()
        guarded_value = _noise_value()
        public_topic = f"victim/public/{report}"
        guarded_topic = f"victim/secret/{report}"

        children: list[CheckResult] = []
        publisher_id = ""
        publisher_password = ""
        device_fixtures: list[tuple[str, str, str]] = []
        fixture_published = False
        try:
            team_id = str(target.meta["team_id"])
            principals = _issued_principals(target)
            publisher_id, publisher_password = facility_publisher(team_id)

            with self._client(
                host, port, publisher_id, publisher_password
            ) as publisher:
                publisher.publish(public_topic, public_value, qos=1, retain=True)
                publisher.publish(guarded_topic, guarded_value, qos=1, retain=True)
                fixture_published = True
            with self._client(
                host, port, publisher_id, publisher_password
            ) as publisher:
                grant = publisher.subscribe(guarded_topic, qos=1)
                fixture_ok = grant in (0, 1) and self._receive_until(
                    publisher, guarded_topic, guarded_value.encode()
                )
            children.append(CheckResult(
                "victim_retained_qos1", fixture_ok, f"SUBACK={grant}"
            ))

            own_results: list[bool] = []
            exact_results: list[bool] = []
            deny_results: list[bool] = []
            wildcard_results: list[bool] = []
            for username, password in principals:
                own_topic = f"tenant/{username}/telemetry/{report}"
                own_value = _noise_value()
                device_fixtures.append((username, password, own_topic))
                with self._client(host, port, username, password) as device:
                    device.publish(own_topic, own_value, qos=1, retain=True)
                with self._client(host, port, username, password) as device:
                    grant = device.subscribe(own_topic, qos=1)
                    own_results.append(
                        grant in (0, 1)
                        and self._receive_until(
                            device, own_topic, own_value.encode()
                        )
                    )

                with self._client(host, port, username, password) as device:
                    grant = device.subscribe(public_topic, qos=1)
                    exact_results.append(
                        grant in (0, 1)
                        and self._receive_until(
                            device, public_topic, public_value.encode()
                        )
                    )

                with self._client(host, port, username, password) as device:
                    denied = device.subscribe(guarded_topic, qos=1)
                    deny_results.append(denied == 0x80)

                with self._client(host, port, username, password) as device:
                    grant = device.subscribe(f"victim/+/{report}", qos=1)
                    wildcard_results.append(
                        grant in (0, 1)
                        and self._receive_until(
                            device, public_topic, public_value.encode()
                        )
                    )
            children.append(CheckResult(
                "own_retained_qos1", all(own_results),
                f"issued={len(principals)}",
            ))
            children.append(CheckResult(
                "public_retained_exact", all(exact_results),
                f"issued={len(principals)}",
            ))
            children.append(CheckResult(
                "guarded_direct_deny", all(deny_results),
                f"issued={len(principals)}",
            ))
            children.append(CheckResult(
                "public_retained_wildcard", all(wildcard_results),
                f"issued={len(principals)}",
            ))
        except (OSError, MqttError, KeyError, RuntimeError, socket.timeout) as error:
            children.append(CheckResult(
                "protocol_exception", False, f"{type(error).__name__}: {error}"
            ))
        finally:
            cleanup_ok = True
            cleanup_errors: list[str] = []
            for username, password, own_topic in device_fixtures:
                try:
                    with self._client(host, port, username, password) as device:
                        device.publish(own_topic, b"", qos=1, retain=True)
                except (OSError, MqttError, socket.timeout) as error:
                    cleanup_ok = False
                    cleanup_errors.append(
                        f"device: {type(error).__name__}: {error}"
                    )
            try:
                if publisher_id and publisher_password:
                    with self._client(
                        host, port, publisher_id, publisher_password
                    ) as publisher:
                        publisher.publish(public_topic, b"", qos=1, retain=True)
                        publisher.publish(guarded_topic, b"", qos=1, retain=True)
            except (OSError, MqttError, socket.timeout) as error:
                cleanup_ok = False
                cleanup_errors.append(f"victim: {type(error).__name__}: {error}")
            children.append(CheckResult(
                "retained_cleanup",
                cleanup_ok,
                "; ".join(cleanup_errors)
                if cleanup_errors
                else (
                    "fresh retained fixture retired"
                    if fixture_published or device_fixtures
                    else "idempotent retained cleanup"
                ),
            ))
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
