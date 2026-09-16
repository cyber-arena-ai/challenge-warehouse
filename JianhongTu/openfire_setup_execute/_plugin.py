"""Construct bounded Openfire plugin archives used by the PoV and checker."""

from __future__ import annotations

import base64
import hashlib
import io
import re
import zipfile


_PROOF_INNER = "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"
_HEALTH_INNER = "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"
_PLUGIN_ID = re.compile(r"[a-z][a-z0-9-]{7,47}")
_PLUGIN_TEXT = re.compile(r"[A-Za-z0-9 ,.()'-]{8,96}")
_PLUGIN_STATUS = re.compile(r"[a-f0-9]{32}")
_TEMPLATE_CLASS = "UtilityPlugin"
_TEMPLATE_CLASS_PATH = (
    "org/igniterealtime/openfire/plugin/utility/UtilityPlugin.class"
)
_PLUGIN_WORDS = (
    "archive",
    "board",
    "calendar",
    "campus",
    "community",
    "contacts",
    "courses",
    "directory",
    "events",
    "groups",
    "library",
    "meetings",
    "messages",
    "notes",
    "projects",
    "resources",
    "rooms",
    "schedule",
    "support",
    "teams",
    "updates",
    "workspace",
)


def ordinary_plugin_identity(entropy: bytes) -> tuple[str, str, str]:
    if len(entropy) < 16:
        raise ValueError("insufficient plugin identity entropy")
    digest = hashlib.sha256(b"openfire:ordinary-plugin-name:v1\0" + entropy).digest()
    first = _PLUGIN_WORDS[int.from_bytes(digest[:4], "big") % len(_PLUGIN_WORDS)]
    second = _PLUGIN_WORDS[int.from_bytes(digest[4:8], "big") % len(_PLUGIN_WORDS)]
    number = int.from_bytes(digest[8:12], "big") % 9000 + 1000
    canonical = f"{first}-{second}-{number}"
    display_name = f"{first.title()} {second.title()}"
    description = (
        f"Provides {first} and {second} features for Openfire communities."
    )
    return canonical, display_name, description


def _letters(status: str, label: str, length: int) -> str:
    digest = hashlib.shake_256(
        label.encode() + b"\0" + bytes.fromhex(status)
    ).digest(length)
    return "".join(chr(ord("a") + value % 26) for value in digest)


def _health_names(status: str) -> tuple[str, str, str, str]:
    if not _PLUGIN_STATUS.fullmatch(status):
        raise ValueError("invalid plugin status")
    package_name = _letters(status, "package", 7)
    simple_name = _letters(status, "class", 13)
    class_name = simple_name[0].upper() + simple_name[1:]
    resource_path = "resources/" + _letters(status, "resource", 7) + ".properties"
    property_suffix = "." + _letters(status, "property", 6)
    return package_name, class_name, resource_path, property_suffix


def _health_inner(status: str) -> tuple[str, str, str, str, bytes]:
    package_name, class_name, resource_path, property_suffix = _health_names(status)
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(_HEALTH_INNER))) as template:
        manifest = template.read("META-INF/MANIFEST.MF")
        bytecode = template.read(_TEMPLATE_CLASS_PATH)
    template_class = (
        b"org/igniterealtime/openfire/plugin/utility/UtilityPlugin"
    )
    varied_class = (
        "org/igniterealtime/openfire/plugin/"
        + package_name
        + "/"
        + class_name
    ).encode()
    replacements = (
        (template_class, varied_class, 1),
        (_TEMPLATE_CLASS.encode(), class_name.encode(), 1),
        (b"resources/utility.properties", resource_path.encode(), 1),
        (b".status", property_suffix.encode(), 1),
        (b"0" * 32, status.encode(), 1),
    )
    for old, new, expected_count in replacements:
        if len(old) != len(new) or bytecode.count(old) != expected_count:
            raise RuntimeError("invalid checker plugin template")
        bytecode = bytecode.replace(old, new)
    class_path = varied_class.decode() + ".class"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", manifest)
        archive.writestr(class_path, bytecode)
    return package_name, class_name, resource_path, property_suffix, output.getvalue()


def _outer(
    plugin_xml: str,
    inner: str | bytes,
    resource: tuple[str, str] | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        inner_bytes = base64.b64decode(inner) if isinstance(inner, str) else inner
        archive.writestr("lib/plugin.jar", inner_bytes)
        archive.writestr("plugin.xml", plugin_xml)
        if resource is not None:
            archive.writestr(*resource)
    return output.getvalue()


def proof_plugin(locator: str) -> tuple[str, bytes]:
    if not re.fullmatch(r"[a-f0-9]{24}", locator):
        raise ValueError("invalid execution locator")
    canonical, display_name, _description = ordinary_plugin_identity(
        hashlib.sha256(
            b"openfire:proof-plugin-name:v1\0" + bytes.fromhex(locator)
        ).digest()
    )
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<plugin>
  <class>arena.ProofPlugin</class>
  <name>{display_name}</name>
  <description>{locator}</description>
  <author>Openfire Community</author>
  <version>1.0</version>
  <minServerVersion>4.7.0</minServerVersion>
</plugin>
"""
    return canonical, _outer(metadata, _PROOF_INNER)


def health_plugin(
    canonical: str, display_name: str, description: str, status: str
) -> bytes:
    if not _PLUGIN_ID.fullmatch(canonical):
        raise ValueError("invalid plugin identifier")
    if not _PLUGIN_TEXT.fullmatch(display_name) or not _PLUGIN_TEXT.fullmatch(
        description
    ):
        raise ValueError("invalid plugin metadata")
    package_name, class_name, resource_path, _property_suffix, inner = (
        _health_inner(status)
    )
    metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<plugin>
  <class>org.igniterealtime.openfire.plugin.{package_name}.{class_name}</class>
  <name>{display_name}</name>
  <description>{description}</description>
  <author>Openfire Community</author>
  <version>1.0</version>
  <minServerVersion>4.7.0</minServerVersion>
</plugin>
"""
    resource = (
        f"name={display_name}\ndescription={description}\nstatus={status}\n"
    )
    return _outer(metadata, inner, (resource_path, resource))


def health_property(canonical: str, status: str) -> str:
    if not _PLUGIN_ID.fullmatch(canonical):
        raise ValueError("invalid plugin identifier")
    _package, _class_name, _resource_path, property_suffix = _health_names(status)
    return "plugin." + canonical + property_suffix
