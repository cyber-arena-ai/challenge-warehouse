"""Small stdlib client for pyLoad's native web and RPC surfaces."""

from __future__ import annotations

import base64
import http.client
import json
import secrets
import string
import urllib.parse

from Crypto.Cipher import AES

PORT = 8000
#: The two Host values the pinned upstream's Click'N'Load `local_check`
#: accepts. It compares `HTTP_HOST` for exact equality against this pair, so
#: no other spelling reaches the endpoints; its other branch tests REMOTE_ADDR,
#: which is the peer address and never loopback for an off-box client.
LOOPBACK_HOSTS = ("127.0.0.1:9666", "[::1]:9666")
_QUOTES = ('"', "'")
_SEPARATORS = "_:"
_GAP_TEXT = string.ascii_letters + string.digits + " "
_GAP_SLOT = "\0"
_URL_LABEL = string.ascii_lowercase + string.digits
_IDENTIFIER_HEAD = string.ascii_letters + "_$"
_IDENTIFIER_TAIL = _IDENTIFIER_HEAD + string.digits
_RESERVED = {
    "Array", "JSON", "Js", "JsRegExp", "Object", "PyJsStrictEq", "Scope",
    "String", "arguments",
    "abstract", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "debugger", "default", "delete", "do", "double",
    "else", "enum", "export", "extends", "false", "final", "finally", "float",
    "for", "function", "goto", "if", "implements", "import", "in",
    "instanceof", "int", "interface", "let", "long", "native", "new", "null",
    "package", "private", "protected", "public", "return", "short", "static",
    "super", "switch", "synchronized", "this", "throw", "throws", "transient",
    "true", "try", "typeof", "var", "void", "volatile", "while", "with",
    "yield", "decodeURIComponent",
}


def _literal(text: str) -> str:
    quote = secrets.choice(_QUOTES)
    encoded = []
    for char in text:
        codepoint = ord(char)
        kind = secrets.randbelow(4)
        if char not in {quote, "\\"} and 32 <= codepoint <= 126 and kind < 2:
            encoded.append(char)
        elif codepoint <= 255 and kind < 3:
            encoded.append(f"\\x{codepoint:02x}")
        else:
            encoded.append(f"\\u{codepoint:04x}")
        if secrets.randbelow(8) == 0:
            # A line continuation is the one newline that is safe inside an
            # expression: it belongs to the string token, so it is not a line
            # terminator *between* tokens and cannot trigger the restricted
            # production `_gap` exists to avoid.
            encoded.append("\\\n")
    return quote + "".join(encoded) + quote


def _identifier() -> str:
    while True:
        value = secrets.choice(_IDENTIFIER_HEAD) + "".join(
            secrets.choice(_IDENTIFIER_TAIL)
            for _ in range(1 + secrets.randbelow(13))
        )
        if value not in _RESERVED:
            return value


def _identifiers(count: int) -> list[str]:
    values: list[str] = []
    while len(values) < count:
        value = _identifier()
        if value not in values:
            values.append(value)
    return values


def _comment_text() -> str:
    return "".join(
        secrets.choice(_GAP_TEXT) for _ in range(secrets.randbelow(12))
    )


def _gap(*, comments: bool) -> str:
    """Reserve or render an insignificant ES5 token boundary.

    Reserved slots are replaced only after the whole program is generated, so
    one randomly selected safe boundary can be guaranteed to carry a block
    comment without imposing a fixed outer envelope. Rendered gaps never contain
    a line terminator: a newline after `return` would end that statement.
    """
    if comments:
        return _GAP_SLOT
    kind = secrets.randbelow(4)
    if kind == 1:
        return "".join(
            secrets.choice(" \t") for _ in range(1 + secrets.randbelow(3))
        )
    return ""


def _optional_internal_gap() -> str:
    kind = secrets.randbelow(4)
    if kind == 0:
        return f"/*{_comment_text()}*/"
    if kind == 1:
        return "".join(
            secrets.choice(" \t") for _ in range(1 + secrets.randbelow(3))
        )
    return ""


def _fill_comment_slots(program: str) -> str:
    parts = program.split(_GAP_SLOT)
    gap_count = len(parts) - 1
    if gap_count < 1:
        raise RuntimeError("generated ES5 program has no safe trivia boundary")
    required_gap = secrets.randbelow(gap_count)
    rendered = [parts[0]]
    for index, part in enumerate(parts[1:]):
        rendered.append(
            f"/*{_comment_text()}*/"
            if index == required_gap
            else _optional_internal_gap()
        )
        rendered.append(part)
    return "".join(rendered)


def _outer_gap(*, comments: bool) -> str:
    whitespace = secrets.choice(("", " ", "\t", "\n", "\r\n", " \n\t"))
    if not comments:
        return whitespace
    kind = secrets.randbelow(4)
    if kind == 0:
        return f"//{_comment_text()}\n{whitespace}"
    if kind == 1:
        return f"/*{_comment_text()}*/{whitespace}"
    return whitespace


def _spaced(fragment: str, *, comments: bool) -> str:
    return f"{_gap(comments=comments)}{fragment}{_gap(comments=comments)}"


def _atom(text: str, *, comments: bool) -> str:
    return _spaced(_atom_form(text), comments=comments)


def _atom_form(text: str) -> str:
    kind = secrets.randbelow(12)
    if kind == 0:
        return _literal(text)
    if kind == 1:
        return f"String.fromCharCode({','.join(str(ord(char)) for char in text)})"
    if kind == 2:
        mark = secrets.choice(_SEPARATORS)
        return f"{_literal(mark.join(text))}.replace(/{mark}/g,{_literal('')})"
    if kind == 3:
        empty = _literal("")
        return f"{_literal(text[::-1])}.split({empty}).reverse().join({empty})"
    if kind == 4:
        prefix = secrets.token_hex(1 + secrets.randbelow(2))
        return (
            f"(Array(3).join({_literal(prefix)})+{_literal(text)})"
            f".slice({len(prefix) * 2})"
        )
    if kind == 5:
        values = ",".join(str(int(char, 16)) for char in text)
        array, output, index = _identifiers(3)
        return (
            f"(function({array}){{var {output}=String(),{index}=0;"
            f"for(;{index}<{array}.length;{index}++){{"
            f"{output}+={array}[{index}].toString(16);}}return {output};}})"
            f"([{values}])"
        )
    if kind == 6:
        encoded = "".join(f"%{ord(char):02x}" for char in text)
        return f"decodeURIComponent({_literal(encoded)})"
    if kind == 7:
        return f"JSON.parse({json.dumps(json.dumps(text))})"
    if kind == 8:
        return f"({_literal(text.upper())}).toLowerCase()"
    if kind == 9:
        return f"/{text}/.source"
    if kind == 10:
        return f"Object.keys({{k{text}:true}})[0].slice(1)"
    values = ",".join(str(int(char, 16)) for char in text)
    table, array, output, index = _identifiers(4)
    return (
        f"(function({table},{array}){{var {output}=String(),{index}=0;"
        f"for(;{index}<{array}.length;{index}++){{"
        f"{output}+={table}.charAt({array}[{index}]);}}return {output};}})"
        f"({_literal('0123456789abcdef')},[{values}])"
    )


def _combine(left: str, right: str, *, comments: bool) -> str:
    return _spaced(_combine_form(left, right), comments=comments)


def _combine_form(left: str, right: str) -> str:
    kind = secrets.randbelow(4)
    if kind == 0:
        return f"(({left})+({right}))"
    if kind == 1:
        return f"[{left},{right}].join({_literal('')})"
    if kind == 2:
        return f"({left}).concat({right})"
    first, second = _identifiers(2)
    return (
        f"(function({first},{second}){{return {first}+{second};}})"
        f"({left},{right})"
    )


def _identity(expression: str, *, comments: bool) -> str:
    return _spaced(_identity_form(expression), comments=comments)


def _identity_form(expression: str) -> str:
    kind = secrets.randbelow(8)
    if kind == 0:
        return f"String({expression})"
    if kind == 1:
        return f"[{expression}].join({_literal('')})"
    if kind == 2:
        value = _identifier()
        return f"(function({value}){{return {value};}})({expression})"
    if kind == 3:
        property_name = _identifier()
        return f"({{{property_name}:{expression}}}).{property_name}"
    if kind == 4:
        return f"({expression}).substr(0)"
    if kind == 5:
        return f"Array(2).join({expression})"
    if kind == 6:
        return f"({expression}).split({_literal('')}).join({_literal('')})"
    return f"(void 0,{expression})"


def _expression(text: str, depth: int, *, comments: bool) -> str:
    if depth == 0 or len(text) < 2 or secrets.randbelow(4) == 0:
        return _atom(text, comments=comments)
    if secrets.randbelow(3) == 0:
        return _identity(
            _expression(text, depth - 1, comments=comments),
            comments=comments,
        )
    split = 1 + secrets.randbelow(len(text) - 1)
    expression = _combine(
        _expression(text[:split], depth - 1, comments=comments),
        _expression(text[split:], depth - 1, comments=comments),
        comments=comments,
    )
    return (
        _identity(expression, comments=comments)
        if secrets.randbelow(2)
        else expression
    )


def _key_expression(text: str, *, comments: bool) -> str:
    depth = 2 + secrets.randbelow(3)
    expression = _expression(text, depth, comments=comments)
    for _ in range(secrets.randbelow(3)):
        expression = _identity(expression, comments=comments)
    return expression


def js_key_expression(key_hex: str, *, require_block_comment: bool) -> str:
    """Render a varied legitimate ES5 key program for `key_hex`.

    The checker source is public, so this is not a secrecy boundary, and a
    defender can always mirror this generator. What the variation removes is
    the fixed *spelling*: composing data encodings, expression wrappers,
    identifiers, control flow and program shapes over insignificant tokens
    leaves the rendered text non-canonical. The commented class places a block
    comment at one randomly selected safe internal boundary and independently
    varies the remaining internal and outer trivia; the other class is
    comment-free with randomized outer whitespace.
    """
    program = _program(key_hex, comments=require_block_comment)
    if require_block_comment:
        program = _fill_comment_slots(program)
    return (
        _outer_gap(comments=require_block_comment)
        + program
        + _outer_gap(comments=require_block_comment)
    )


def _program(key_hex: str, *, comments: bool) -> str:
    expression = _key_expression(key_hex, comments=comments)
    value, noise, helper, holder = _identifiers(4)
    kind = secrets.randbelow(10)
    if kind == 0:
        body = f"return {expression};"
    elif kind == 1:
        body = f"var {noise}={secrets.randbelow(997)};return {expression};"
    elif kind == 2:
        body = (
            f"var {noise}={_literal(secrets.token_hex(3))},{value}={expression};"
            f"return {value};"
        )
    elif kind == 3:
        body = (
            f"var {helper}=function(){{return {expression};}};"
            f"return {helper}();"
        )
    elif kind == 4:
        body = (
            f"function {helper}(){{return {expression};}}"
            f"var {noise}=[];return {helper}();"
        )
    elif kind == 5:
        body = (
            f"var {value}={expression};if({value}.length===32)"
            f"{{return {value};}}return {_literal('')};"
        )
    elif kind == 6:
        body = (
            f"var {value}={expression};return {value}.substr(0,{value}.length);"
        )
    elif kind == 7:
        body = (
            f"var {value}={expression};switch({value}.length){{"
            f"case 32:return {value};default:return {_literal('')};}}"
        )
    elif kind == 8:
        body = (
            f"var {helper}={{get:function(){{return {expression};}}}};"
            f"return {helper}.get();"
        )
    else:
        body = (
            f"var {value}={expression},{noise}=0;do{{{noise}++;}}"
            f"while({noise}<1);return {value};"
        )

    body = _spaced(body, comments=comments)
    program = secrets.randbelow(10)
    if program == 0:
        return f"function f(){{{body}}}"
    if program == 1:
        return f"var f=function(){{{body}}};"
    if program == 2:
        return f"var f=function {helper}(){{{body}}};"
    if program == 3:
        return f"this.f=function(){{{body}}};"
    if program == 4:
        return f"var f;f=function(){{{body}}};"
    if program == 5:
        return f"var {holder}={{run:function(){{{body}}}}};var f={holder}.run;"
    if program == 6:
        return f"var f=(function(){{return function(){{{body}}};}})();"
    if program == 7:
        return (
            f"var f=(function({helper}){{return {helper};}})"
            f"(function(){{{body}}});"
        )
    if program == 8:
        return f"var f;(function(){{f=function(){{{body}}};}})();"
    return (
        f"var {holder}=function(){{{body}}};"
        f"var f={holder};"
    )


def request(
    host: str,
    path: str,
    *,
    fields: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 12,
    port: int = PORT,
) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    body = None if fields is None else urllib.parse.urlencode(fields).encode()
    request_headers = dict(headers or {})
    if fields is not None:
        request_headers.setdefault(
            "Content-Type", "application/x-www-form-urlencoded"
        )
    try:
        connection.request(
            "GET" if fields is None else "POST",
            path,
            body=body,
            headers=request_headers,
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def rpc(
    host: str,
    method: str,
    username: str,
    password: str,
    *,
    port: int = PORT,
    **arguments: object,
) -> tuple[int, bytes]:
    fields = {"u": username, "p": password}
    # pyLoad unquotes RPC arguments again after normal form decoding.
    fields.update(
        {key: repr(value).replace("%", "%25") for key, value in arguments.items()}
    )
    return request(host, f"/api/{method}", fields=fields, port=port)


def document(status: int, body: bytes, operation: str) -> object:
    if status != 200:
        raise RuntimeError(f"{operation} returned HTTP {status}")
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{operation} returned malformed JSON") from error


def status_document(
    host: str, username: str, password: str, *, port: int = PORT
) -> dict:
    status, body = rpc(host, "status_server", username, password, port=port)
    value = document(status, body, "status_server")
    if not isinstance(value, dict):
        raise RuntimeError("status_server returned the wrong shape")
    return value


def guarded_status(
    host: str, username: str, password: str, *, port: int = PORT
) -> int:
    status, _ = rpc(host, "get_config", username, password, port=port)
    return status


def _url_piece(minimum: int, maximum: int) -> str:
    length = minimum + secrets.randbelow(maximum - minimum + 1)
    return "".join(secrets.choice(_URL_LABEL) for _ in range(length))


def _url_host() -> str:
    kind = secrets.randbelow(5)
    if kind == 0:
        labels = [_url_piece(1, 16) for _ in range(1 + secrets.randbelow(3))]
        labels.append(
            "".join(
                secrets.choice(string.ascii_lowercase)
                for _ in range(2 + secrets.randbelow(10))
            )
        )
        return ".".join(labels)
    if kind == 1:
        return f"192.0.2.{1 + secrets.randbelow(254)}"
    if kind == 2:
        return f"198.51.100.{1 + secrets.randbelow(254)}"
    if kind == 3:
        return f"[2001:db8::{1 + secrets.randbelow(65535):x}]"
    return secrets.choice(("example.com", "example.net", "example.org"))


def _download_url() -> str:
    if secrets.randbelow(16) == 0:
        return "http://example.com"
    scheme = secrets.choice(("http", "https"))
    host = _url_host()
    if secrets.randbelow(4) == 0:
        host += f":{1024 + secrets.randbelow(64512)}"
    segments = [_url_piece(1, 24) for _ in range(secrets.randbelow(5))]
    if segments and secrets.randbelow(4):
        segments[-1] += secrets.choice((".bin", ".dat", ".pdf", ".tar.gz", ".zip"))
    url = f"{scheme}://{host}"
    if segments:
        url += "/" + "/".join(segments)
    if secrets.randbelow(3) == 0:
        fields = {
            _url_piece(1, 10): _url_piece(0, 24)
            for _ in range(1 + secrets.randbelow(3))
        }
        url += "?" + urllib.parse.urlencode(fields)
    return url


def add_encrypted_package(
    host: str,
    package: str,
    url: str,
    *,
    host_header: str,
    require_block_comment: bool,
    port: int = PORT,
) -> tuple[int, bytes]:
    key = secrets.token_bytes(16)
    key_hex = key.hex()
    plaintext = (url + "\n").encode()
    plaintext += b"\0" * (-len(plaintext) % AES.block_size)
    crypted = base64.b64encode(
        AES.new(key, AES.MODE_CBC, iv=key).encrypt(plaintext)
    ).decode()
    expression = js_key_expression(
        key_hex, require_block_comment=require_block_comment
    )
    status, body = request(
        host,
        "/flash/addcrypted2",
        fields={"package": package, "crypted": crypted, "jk": expression},
        headers={"Host": host_header},
        port=port,
    )
    return status, body


def package_rows(value: object) -> list[dict]:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise RuntimeError("collector returned the wrong shape")
    return value
