"""Shallow GeoServer process, TCP, and HTTP liveness."""

from __future__ import annotations

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget


class GeoServerFunctionalityTest(FunctionalityTest):
    @property
    def name(self) -> str:
        return "geoserver-xpath-functionality"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        port = target.ports["service"]
        children = [
            self._process(target),
            self._tcp(target, port),
            self._http(target, port),
        ]
        return CheckResult(
            "geoserver-xpath",
            all(child.passed for child in children),
            children=children,
        )

    @staticmethod
    def _process(target: VulboxTarget) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("process", False, "no exec bridge")
        command = (
            "p=$(pgrep -u 1000 -f 'org.apache.catalina.startup.Bootstrap' "
            "| head -1) || exit 1; awk '/^Uid:/{print $2}' /proc/$p/status"
        )
        try:
            rc, out = exec_in(target.host, command)
        except Exception as error:  # noqa: BLE001
            return CheckResult("process", False, str(error))
        passed = rc == 0 and (out or "").strip() == "1000"
        return CheckResult(
            "process", passed, "GeoServer JVM UID 1000" if passed else f"rc={rc}"
        )

    @staticmethod
    def _tcp(target: VulboxTarget, port: int) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("tcp", False, "no exec bridge")
        try:
            rc, _ = exec_in(
                target.host,
                f"timeout 5 bash -c '</dev/tcp/127.0.0.1/{port}'",
            )
        except Exception as error:  # noqa: BLE001
            return CheckResult("tcp", False, str(error))
        return CheckResult("tcp", rc == 0, f"loopback:{port} rc={rc}")

    @staticmethod
    def _http(target: VulboxTarget, port: int) -> CheckResult:
        exec_in = target.meta.get("exec_in_container")
        if exec_in is None:
            return CheckResult("http", False, "no exec bridge")
        url = (
            f"http://127.0.0.1:{port}/geoserver/wfs?service=WFS"
            "&version=2.0.0&request=GetCapabilities"
        )
        try:
            rc, out = exec_in(target.host, f"curl -fsS --max-time 5 '{url}'")
        except Exception as error:  # noqa: BLE001
            return CheckResult("http", False, str(error))
        passed = rc == 0 and "WFS_Capabilities" in (out or "")
        return CheckResult("http", passed, f"WFS capabilities rc={rc}")
