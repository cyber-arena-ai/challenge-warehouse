"""Small stdlib Jenkins HTTP client and native job configuration builders."""

from __future__ import annotations

import base64
import http.cookiejar
import json
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def _basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return "Basic " + token


class JenkinsClient:
    def __init__(self, base: str, username: str, password: str) -> None:
        self.base = base.rstrip("/")
        self.auth = _basic(username, password)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self._crumb: dict[str, str] | None = None

    def request(
        self,
        path: str,
        *,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        method: str | None = None,
        timeout: float = 15,
    ) -> tuple[int, bytes]:
        request_headers = {"Authorization": self.auth}
        request_headers.update(headers or {})
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=request_headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    @property
    def crumb(self) -> dict[str, str]:
        if self._crumb is None:
            status, raw = self.request("/crumbIssuer/api/json")
            if status != 200:
                raise RuntimeError(f"Jenkins crumb request returned HTTP {status}")
            document = json.loads(raw)
            field = document.get("crumbRequestField")
            value = document.get("crumb")
            if not isinstance(field, str) or not isinstance(value, str):
                raise RuntimeError("Jenkins crumb response was malformed")
            self._crumb = {field: value}
        return self._crumb

    def json(self, path: str) -> tuple[int, object]:
        status, raw = self.request(path)
        try:
            return status, json.loads(raw) if raw else None
        except ValueError:
            return status, None

    def job_config(self, name: str) -> tuple[int, bytes]:
        return self.request(f"/job/{urllib.parse.quote(name)}/config.xml")

    def configure_job(self, name: str, body: bytes) -> int:
        status, _ = self.request(
            f"/job/{urllib.parse.quote(name)}/config.xml",
            data=body,
            headers={**self.crumb, "Content-Type": "application/xml"},
        )
        return status

    def create_job(self, name: str, body: bytes) -> int:
        status, _ = self.request(
            "/createItem?" + urllib.parse.urlencode({"name": name}),
            data=body,
            headers={**self.crumb, "Content-Type": "application/xml"},
        )
        return status

    def delete_job(self, name: str) -> int:
        status, _ = self.request(
            f"/job/{urllib.parse.quote(name)}/doDelete",
            data=b"",
            headers=self.crumb,
        )
        return status

    def run_script(self, script: str) -> tuple[int, bytes]:
        return self.request(
            "/scriptText",
            data=urllib.parse.urlencode({"script": script}).encode(),
            headers={
                **self.crumb,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )


def set_description(raw: bytes, description: str) -> bytes:
    root = ET.fromstring(raw)
    element = root.find("./description")
    if element is None:
        element = ET.Element("description")
        root.insert(0, element)
    element.clear()
    element.text = description
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def get_description(raw: bytes) -> str | None:
    return ET.fromstring(raw).findtext("./description")


def set_script(raw: bytes, script: str) -> bytes:
    root = ET.fromstring(raw)
    element = root.find("./definition/script")
    if element is None:
        raise ValueError("Jenkins Pipeline definition is missing")
    element.text = script
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def get_script(raw: bytes) -> str | None:
    return ET.fromstring(raw).findtext("./definition/script")


def protected_job_xml(description: str) -> bytes:
    root = ET.Element("flow-definition", {"plugin": "workflow-job"})
    ET.SubElement(root, "actions")
    ET.SubElement(root, "description").text = description
    ET.SubElement(root, "keepDependencies").text = "false"
    ET.SubElement(root, "properties")
    definition = ET.SubElement(
        root,
        "definition",
        {"class": "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition", "plugin": "workflow-cps"},
    )
    ET.SubElement(definition, "script").text = (
        "node('untrusted') { deleteDir(); writeFile file: 'protected.txt', "
        "text: 'protected'; archiveArtifacts artifacts: 'protected.txt' }"
    )
    ET.SubElement(definition, "sandbox").text = "true"
    ET.SubElement(root, "triggers")
    ET.SubElement(root, "disabled").text = "false"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def checker_job_xml(
    description: str, ordinary_user: str, *, allow_configure: bool = False
) -> bytes:
    root = ET.fromstring(protected_job_xml(description))
    properties = root.find("./properties")
    assert properties is not None
    parameters = ET.SubElement(
        properties,
        "hudson.model.ParametersDefinitionProperty",
    )
    definitions = ET.SubElement(parameters, "parameterDefinitions")
    parameter = ET.SubElement(
        definitions,
        "hudson.model.StringParameterDefinition",
    )
    ET.SubElement(parameter, "name").text = "TOKEN"
    ET.SubElement(parameter, "defaultValue").text = "missing"
    ET.SubElement(parameter, "trim").text = "false"
    matrix = ET.SubElement(
        properties,
        "hudson.security.AuthorizationMatrixProperty",
    )
    ET.SubElement(
        matrix,
        "inheritanceStrategy",
        {"class": "org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy"},
    )
    permissions = ["Build", "Read", "Workspace"]
    if allow_configure:
        permissions.append("Configure")
    for permission in permissions:
        ET.SubElement(matrix, "permission").text = (
            f"hudson.model.Item.{permission}:{ordinary_user}"
        )
    script = root.find("./definition/script")
    assert script is not None
    script.text = """
node('untrusted') {
    deleteDir()
    writeFile file: 'probe.txt', text: params.TOKEN
    sh 'mkdir safe-target && printf %s "$TOKEN" > safe-target/value.txt && ln -s safe-target safe-link'
    archiveArtifacts artifacts: 'probe.txt,safe-link/**', followSymlinks: true
}
""".strip()
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
