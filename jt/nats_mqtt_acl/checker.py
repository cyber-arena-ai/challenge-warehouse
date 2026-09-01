"""External MQTT checker using the same public account as ordinary players."""

from __future__ import annotations

import secrets
import socket
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._ids import ATTACK_PASSWORD, ATTACK_USERNAME
from ._mqtt import MqttClient, MqttError, resolve_host


class NatsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        host = resolve_host(target.host)
        port = target.ports["service"]
        suffix = secrets.token_hex(8)
        own_topic = f"tenant/{ATTACK_USERNAME}/{secrets.token_hex(6)}/{suffix}"
        own_payload = "own-" + secrets.token_hex(10)
        children: list[CheckResult] = []
        try:
            with self._client(host, port) as user:
                user.publish(own_topic, own_payload)

            with self._client(host, port) as user:
                grant = user.subscribe(own_topic, qos=1)
                topic, payload, _ = user.receive(timeout=5)
                own_ok = (
                    grant in (0, 1)
                    and topic == own_topic
                    and payload.decode() == own_payload
                )
            children.append(
                CheckResult(
                    "own_retained_qos1", own_ok,
                    f"grant={grant}, topic={topic!r}",
                )
            )

            public_topic = ""
            public_payload = b""
            with self._client(host, port) as user:
                grant = user.subscribe("victim/public/>", qos=1)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    topic, payload, _ = user.receive(
                        timeout=max(0.1, deadline - time.monotonic()))
                    if topic.startswith("victim/public/"):
                        public_topic = topic
                        public_payload = payload
                        break
            public_ok = (
                grant in (0, 1) and bool(public_topic) and bool(public_payload)
            )
            children.append(
                CheckResult(
                    "public_retained_telemetry", public_ok,
                    f"grant={grant}, topic={public_topic!r}",
                )
            )
            if not public_ok:
                return CheckResult("checker", False, children=children)

            retained_suffix = public_topic.rsplit("/", 1)[-1]
            guarded_topic = f"victim/secret/{retained_suffix}"
            with self._client(host, port) as user:
                denied = user.subscribe(guarded_topic)
            children.append(
                CheckResult(
                    "guarded_direct_deny", denied == 0x80,
                    f"SUBACK={denied}",
                )
            )

            with self._client(host, port) as user:
                grant = user.subscribe(f"victim/+/{retained_suffix}", qos=1)
                seen_public = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        topic, payload, _ = user.receive(
                            timeout=max(0.1, deadline - time.monotonic()))
                    except socket.timeout:
                        break
                    if topic == public_topic and payload == public_payload:
                        seen_public = True
                        break
            children.append(
                CheckResult(
                    "public_wildcard", grant in (0, 1) and seen_public,
                    f"grant={grant}, public={seen_public}",
                )
            )
        except (OSError, MqttError, UnicodeError, socket.timeout) as error:
            children.append(CheckResult("protocol_exception", False, str(error)))
        finally:
            try:
                with self._client(host, port) as user:
                    user.publish(own_topic, b"")
            except (OSError, MqttError):
                pass
        return CheckResult(
            "checker", bool(children) and all(c.passed for c in children),
            children=children,
        )

    @staticmethod
    def _client(host: str, port: int) -> MqttClient:
        return MqttClient(host, port, ATTACK_USERNAME, ATTACK_PASSWORD,
                          client_id="mqtt-" + secrets.token_hex(10))
