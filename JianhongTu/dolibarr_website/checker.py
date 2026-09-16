"""External semantic checker for restricted-editor Website publication."""

from __future__ import annotations

import re
import secrets
import string

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._client import (
    DolibarrError,
    create_site_and_page,
    login,
    render_public,
    update_page,
)
from .checker_identity import issued_editors


_REFERENCE_FIRST = string.ascii_letters
_REFERENCE_REST = string.ascii_letters + string.digits + "_"
_LOWER = string.ascii_lowercase
_ALNUM = string.ascii_letters + string.digits
_TEXT = "".join(chr(code) for code in range(0x20, 0x7F) if code not in (0x3C, 0x7E))
_TEXT += "\n"
_ATTRIBUTE_VALUE = _ALNUM + "-_.:/"
_COMMON_TAGS = (
    "a",
    "article",
    "aside",
    "blockquote",
    "code",
    "details",
    "div",
    "em",
    "figcaption",
    "figure",
    "footer",
    "h1",
    "h2",
    "h3",
    "iframe",
    "label",
    "main",
    "mark",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "span",
    "strong",
    "summary",
    "svg",
    "table",
    "ul",
)
_ATTRIBUTES = (
    "alt",
    "class",
    "height",
    "href",
    "id",
    "lang",
    "rel",
    "role",
    "src",
    "style",
    "title",
    "width",
)
_BOOLEAN_ATTRIBUTES = ("contenteditable", "draggable", "hidden", "itemscope")
_ENTITIES = (
    "&amp;",
    "&lt;",
    "&gt;",
    "&quot;",
    "&nbsp;",
    "&copy;",
    "&#65;",
    "&#x42;",
)
_BMP_RANGES = (
    (0x00C0, 0x00FF),
    (0x0391, 0x03CA),
    (0x0410, 0x0450),
    (0x05D0, 0x05EB),
    (0x0627, 0x064B),
    (0x4E00, 0x4E80),
)


def _draw(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _shuffle(values: list) -> None:
    for index in range(len(values) - 1, 0, -1):
        chosen = secrets.randbelow(index + 1)
        values[index], values[chosen] = values[chosen], values[index]


def _reference() -> str:
    """Return a broad, stable-under-Dolibarr site or page reference."""

    value = secrets.choice(_REFERENCE_FIRST) + _draw(
        _REFERENCE_REST, 7 + secrets.randbelow(57)
    )
    if secrets.randbelow(2):
        split = 1 + secrets.randbelow(len(value) - 1)
        value = value[:split] + "-" + value[split:]
    return value


def _name() -> str:
    return _draw(_LOWER, 2 + secrets.randbelow(7))


def _value() -> str:
    return secrets.choice(_ALNUM) + _draw(
        _ATTRIBUTE_VALUE, 3 + secrets.randbelow(20)
    )


def _tag() -> str:
    style = secrets.randbelow(10)
    if style < 5:
        return secrets.choice(_COMMON_TAGS)
    if style == 5:
        return f"{_name()}-{_name()}"
    if style == 6:
        return f"{_name()}:{_name()}"
    if style == 7:
        name = secrets.choice(_COMMON_TAGS)
        return name.upper() if secrets.randbelow(2) else name.title()
    name = _name()
    return f"{name}x" if name == "head" else name


def _relative_link(prefix: str) -> str:
    """A relative link target the pinned renderer serves back unchanged.

    Its public branch rewrites an href that ends in `.php` and one that carries
    no `/` (htdocs/core/lib/website.lib.php, the USEDOLIBARRSERVER branch). The
    prefix supplies the `/`; the suffix is kept out of reach here.
    """
    value = f"{prefix}/{_value()}"
    return f"{value}{secrets.choice(_ALNUM)}" if value.endswith(".php") else value


def _attributes() -> str:
    out: list[str] = []
    for _ in range(secrets.randbelow(5)):
        style = secrets.randbelow(4)
        if style == 0:
            out.append(secrets.choice(_BOOLEAN_ATTRIBUTES))
            continue
        name_style = secrets.randbelow(5)
        if name_style < 3:
            name = secrets.choice(_ATTRIBUTES)
        elif name_style == 3:
            name = "data-" + _name()
        else:
            name = "aria-" + _name()
        value = _value()
        if name in ("href", "src"):
            value = _relative_link(_name())
        if style == 1:
            out.append(f"{name}={value}")
        elif style == 2:
            out.append(f"{name}='{value}'")
        else:
            out.append(f'{name}="{value}"')
    return "" if not out else " " + " ".join(out)


def _text() -> str:
    body = _draw(_TEXT, 8 + secrets.randbelow(72))
    if secrets.randbelow(3) == 0:
        body += secrets.choice(_ENTITIES)
    if secrets.randbelow(4) == 0:
        start, stop = secrets.choice(_BMP_RANGES)
        alphabet = "".join(chr(code) for code in range(start, stop))
        body += _draw(alphabet, 1 + secrets.randbelow(8))
    return body


def _node(depth: int) -> str:
    if depth == 0 or secrets.randbelow(4) == 0:
        return _text()
    child_count = 1 + secrets.randbelow(3)
    tag = _tag()
    children = "".join(_node(depth - 1) for _ in range(child_count))
    return f"<{tag}{_attributes()}>{children}</{tag}>"


def _table() -> str:
    rows = 1 + secrets.randbelow(3)
    cells = 1 + secrets.randbelow(3)
    body = "".join(
        "<tr>"
        + "".join(f"<td{_attributes()}>{_text()}</td>" for _ in range(cells))
        + "</tr>"
        for _ in range(rows)
    )
    return f"<table{_attributes()}>{body}</table>"


def _list() -> str:
    tag = secrets.choice(("ol", "ul"))
    items = "".join(
        f"<li{_attributes()}>{_text()}</li>"
        for _ in range(1 + secrets.randbelow(5))
    )
    return f"<{tag}{_attributes()}>{items}</{tag}>"


def _script() -> str:
    name = _name()
    value = _value()
    forms = (
        f"const {name}='{value}';",
        f"window['{name}']='{value}';",
        f"document.documentElement.dataset.{name}='{value}';",
    )
    return f"<script{_attributes()}>{secrets.choice(forms)}</script>"


def _style() -> str:
    selector = _name()
    declaration = secrets.choice(
        (
            "color:inherit",
            "display:block",
            "margin:0",
            "padding:1px",
            "white-space:normal",
        )
    )
    return f"<style{_attributes()}>.{selector}{{{declaration}}}</style>"


def _comment() -> str:
    return f"<!-- {_draw(_TEXT.replace('-', ''), 8 + secrets.randbelow(48))} -->"


def _media() -> str:
    value = _value()
    forms = (
        f'<img src="assets/{value}" alt="{_value()}" />',
        f'<a href="{_relative_link("pages")}"{_attributes()}>{_text()}</a>',
        f"<input name=\"{_name()}\" value='{value}' />",
        f'<br{_attributes()} />',
        f'<hr{_attributes()} />',
    )
    return secrets.choice(forms)


def _multilingual() -> str:
    start, stop = secrets.choice(_BMP_RANGES)
    alphabet = "".join(chr(code) for code in range(start, stop))
    return _draw(alphabet, 1 + secrets.randbelow(16))


def _entity() -> str:
    return f"{_text()}{secrets.choice(_ENTITIES)}{_text()}"


def _rich_document(*, full: bool) -> str:
    fragments = [_node(1 + secrets.randbelow(4))]
    optional = [
        _node,
        _table,
        _list,
        _script,
        _style,
        _comment,
        _media,
        _multilingual,
        _entity,
    ]
    _shuffle(optional)
    for factory in optional[: 2 + secrets.randbelow(4)]:
        fragment = factory(1 + secrets.randbelow(3)) if factory is _node else factory()
        fragments.append(fragment)
    _shuffle(fragments)
    separator = secrets.choice(("", "\n", "\n  "))
    body = separator.join(fragments)
    if full:
        return (
            f"<!DOCTYPE html><html{_attributes()}>"
            f"<body{_attributes()}>{body}</body></html>"
        )
    if secrets.randbelow(2):
        tag = _tag()
        return f"<{tag}{_attributes()}>{body}</{tag}>"
    return body


_MEDIA_PREFIX = "/viewimage.php?modulepart=medias&file="
# The three <img> rules of the pinned build's public render path, ported in
# order from htdocs/core/lib/website.lib.php (the USEDOLIBARRSERVER branch).
# `_GUARD` is that code's own "!~!~!~" sentinel, which keeps an already
# rewritten source from matching again because the generic rule excludes "!".
_GUARD = "!~!~!~"
_MEDIAS_SOURCE = re.compile(r'(<img[^>]*src=")/?medias/')
_IMAGE_SOURCE = re.compile(r'(<img[^>]*src=")/?([^:"!]+)(")')


def _expected_rendering(document: str) -> str:
    """The submitted document as the pinned renderer serves it back."""
    content = document.replace(
        'src="viewimage.php', f'src="{_GUARD}/viewimage.php'
    ).replace('src="/viewimage.php', f'src="{_GUARD}/viewimage.php')
    content = _MEDIAS_SOURCE.sub(
        lambda match: match.group(1) + _GUARD + _MEDIA_PREFIX, content
    )
    content = _IMAGE_SOURCE.sub(
        lambda match: (
            match.group(1) + _GUARD + _MEDIA_PREFIX + match.group(2) + match.group(3)
        ),
        content,
    )
    return content.replace(_GUARD, "")


def _publication_document() -> str:
    """Build an open-ended page inside the measured byte-exact native surface.

    Plain, simple, structured, and full-document families all occur. Astral
    text and the ``<?`` sequence are absent. Tag ``head``, root- or fragment-
    relative ``href``/``src`` values, and Dolibarr's internal protection marker
    are omitted because the native renderer transforms them.
    """

    mode = secrets.randbelow(4)
    if mode == 0:
        return _text()
    if mode == 1:
        return _node(1 + secrets.randbelow(2))
    return _rich_document(full=mode == 3)


class DolibarrWebsiteChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "dolibarr-website-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        base_url = f"http://{target.host}:{target.ports['service']}"
        editors = issued_editors(target)
        failures: list[str] = []
        try:
            for username, password in editors:
                editor, editor_token = login(base_url, username, password)
                site_ref = _reference()
                page_ref = _reference()
                content = _publication_document()
                page_id = create_site_and_page(
                    editor, editor_token, site_ref, page_ref
                )
                update_page(editor, editor_token, site_ref, page_id, content)
                rendered = render_public(base_url, site_ref, page_ref)
                if _expected_rendering(content) not in rendered:
                    failures.append(f"{username}: document was not preserved")
        except (DolibarrError, OSError) as exc:
            failures.append(f"workflow failed: {type(exc).__name__}")
        return CheckResult(
            name="checker",
            passed=not failures,
            detail=(
                "; ".join(failures)
                if failures
                else f"{len(editors)} issued editors published broad fresh HTML"
            ),
        )
