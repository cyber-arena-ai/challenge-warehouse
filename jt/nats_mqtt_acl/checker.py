"""External checker for retained QoS1 and the declared MQTT ACL boundary."""

from __future__ import annotations

import json
import secrets
import socket
import time

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._mqtt import MqttClient, MqttError, resolve_host


class NatsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "nats-mqtt-acl-checker"

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
            checker = bundle["checker"]
            victim = bundle["victim"]
        except (KeyError, TypeError, json.JSONDecodeError):
            return CheckResult("checker", False, "facility bundle unavailable")

        host = resolve_host(target.host)
        port = target.ports["service"]
        suffix = secrets.token_hex(8)
        own_topic = f"tenant/{checker['username']}/health/{suffix}"
        public_topic = f"victim/public/{suffix}"
        guarded_topic = f"victim/secret/{suffix}"
        own_payload = "own-" + secrets.token_hex(10)
        public_payload = "public-" + secrets.token_hex(10)
        guarded_payload = "guarded-" + secrets.token_hex(10)
        children: list[CheckResult] = []
        try:
            with self._client(host, port, victim, "check-victim-pub") as owner:
                owner.publish(public_topic, public_payload)
                owner.publish(guarded_topic, guarded_payload)
            with self._client(host, port, checker, "check-own-pub") as user:
                user.publish(own_topic, own_payload)

            with self._client(host, port, checker, "check-own-sub") as user:
                grant = user.subscribe(own_topic, qos=1)
                topic, payload, _ = user.receive(timeout=5)
                own_ok = grant in (0, 1) and topic == own_topic and payload.decode() == own_payload
            children.append(CheckResult("own_retained_qos1", own_ok,
                                        f"grant={grant}, topic={topic!r}"))

            with self._client(host, port, checker, "check-denied") as user:
                denied = user.subscribe(guarded_topic)
            children.append(CheckResult("guarded_direct_deny", denied == 0x80,
                                        f"SUBACK={denied}"))

            with self._client(host, port, checker, "check-wildcard") as user:
                grant = user.subscribe(f"victim/+/{suffix}", qos=1)
                seen_public = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        topic, payload, _ = user.receive(
                            timeout=max(0.1, deadline - time.monotonic()))
                    except socket.timeout:
                        break
                    if topic == public_topic and payload.decode() == public_payload:
                        seen_public = True
                        break
            children.append(CheckResult("public_wildcard", grant in (0, 1) and seen_public,
                                        f"grant={grant}, public={seen_public}"))

            with self._client(host, port, victim, "check-victim-sub") as owner:
                grant = owner.subscribe(guarded_topic, qos=1)
                topic, payload, _ = owner.receive(timeout=5)
                victim_ok = grant in (0, 1) and topic == guarded_topic \
                    and payload.decode() == guarded_payload
            children.append(CheckResult("victim_authorized", victim_ok,
                                        f"grant={grant}, topic={topic!r}"))
        except (OSError, MqttError, UnicodeError, socket.timeout) as error:
            children.append(CheckResult("protocol_exception", False, str(error)))
        finally:
            try:
                with self._client(host, port, victim, "check-clean-victim") as owner:
                    owner.publish(public_topic, b"")
                    owner.publish(guarded_topic, b"")
                with self._client(host, port, checker, "check-clean-own") as user:
                    user.publish(own_topic, b"")
            except (OSError, MqttError):
                pass
        return CheckResult("checker", bool(children) and all(c.passed for c in children),
                           children=children)

    @staticmethod
    def _client(host: str, port: int, credentials: dict, client_id: str) -> MqttClient:
        return MqttClient(host, port, credentials["username"], credentials["password"],
                          client_id=client_id)
