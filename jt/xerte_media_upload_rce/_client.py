"""Small stdlib Xerte client shared by the checker, handler, and private PoV."""

from __future__ import annotations

import base64
import http.cookiejar
import re
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 20
WEBROOT = "/srv/runtime/xerte"
LOGIN_FORM_MARKER = b'id="login_box"'
NEW_PROJECT_RE = re.compile(rb"^\s*(\d+),")
_BROWSER_PLATFORMS = (
    "X11; Linux x86_64",
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
)
_BROWSER_ACCEPTS = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
)
_BROWSER_LANGUAGES = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8",
)


def _browser_user_agent() -> str:
    platform = secrets.choice(_BROWSER_PLATFORMS)
    major = 126 + secrets.randbelow(20)
    if secrets.randbelow(2):
        build = 6200 + secrets.randbelow(1800)
        patch = 20 + secrets.randbelow(180)
        return (
            f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{major}.0.{build}.{patch} Safari/537.36"
        )
    return (
        f"Mozilla/5.0 ({platform}; rv:{major}.0) Gecko/20100101 "
        f"Firefox/{major}.0"
    )


def _browser_headers() -> dict[str, str]:
    return {
        "User-Agent": _browser_user_agent(),
        "Accept": secrets.choice(_BROWSER_ACCEPTS),
        "Accept-Language": secrets.choice(_BROWSER_LANGUAGES),
    }


def resolve_host(host: str) -> str:
    """Use the framework-provided address unchanged in every probe context."""
    return host


def elfinder_hash(name: str) -> str:
    encoded = base64.b64encode(name.encode()).decode().rstrip("=")
    return "l1_" + encoded.replace("+", "-").replace("/", "_")


def multipart(fields: dict, file_field: str, filename: str, content: bytes,
              content_type: str = "text/plain") -> tuple[bytes, str]:
    boundary = "----WebKitFormBoundary" + "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(18)
    )
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks += [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode(),
            str(value).encode(), b"\r\n",
        ]
    chunks += [
        f"--{boundary}\r\n".encode(),
        (f'Content-Disposition: form-data; name="{file_field}"; '
         f'filename="{filename}"\r\n').encode(),
        f"Content-Type: {content_type}\r\n\r\n".encode(),
        content, b"\r\n", f"--{boundary}--\r\n".encode(),
    ]
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


class Session:
    """One Xerte browser session (its own cookie jar)."""

    def __init__(self, base: str, *, follow_redirects: bool = True):
        self.base = base.rstrip("/") + "/"
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if not follow_redirects:
            handlers.append(_NoRedirect())
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = list(_browser_headers().items())

    def request(self, path: str, *, data: bytes | None = None,
                headers: dict | None = None,
                method: str | None = None) -> tuple[int, bytes]:
        url = urllib.parse.urljoin(self.base, path)
        request = urllib.request.Request(
            url, data=data, headers=headers or {}, method=method)
        try:
            with self._opener.open(request, timeout=TIMEOUT) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def form(self, path: str, values: dict) -> tuple[int, bytes]:
        return self.request(
            path, data=urllib.parse.urlencode(values).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def public_get(base: str, path: str) -> tuple[int, bytes]:
    url = urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    request = urllib.request.Request(url, headers=_browser_headers())
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except OSError:
        return 0, b""


class XerteApi:
    """Application operations, all through Xerte's own public/guarded surface."""

    def __init__(self, base: str):
        self.base = base.rstrip("/") + "/"

    def login(self, username: str, password: str) -> Session | None:
        session = Session(self.base)
        status, body = session.form("index.php",
                                    {"login": username, "password": password})
        if status != 200 or LOGIN_FORM_MARKER in body:
            return None
        return session

    def add_user(self, admin: Session, username: str, password: str,
                 firstname: str, surname: str, email: str) -> tuple[int, bytes]:
        """Xerte's supported Db user-management operation, at the site
        authority that normally manages accounts."""
        return admin.form(
            "library/Xerte/Authentication/Db/adduser.php",
            {"username": username, "firstname": firstname, "surname": surname,
             "password": password, "email": email})

    def create_project(self, session: Session, name: str) -> int | None:
        status, body = session.form(
            "website_code/php/templates/new_template.php",
            {"templatename": "Nottingham", "tutorialname": name})
        match = NEW_PROJECT_RE.match(body)
        if status != 200 or not match:
            return None
        return int(match.group(1))

    def connector_url(self, project_path: str, webroot: str = WEBROOT) -> str:
        params = {
            "uploadDir": webroot.rstrip("/") + project_path.rstrip("/"),
            "uploadURL": project_path.lstrip("/"),
        }
        return "editor/elfinder/php/connector.php?" + urllib.parse.urlencode(params)

    def upload_media(self, session: Session, project_path: str, filename: str,
                     content: bytes, content_type: str = "text/plain",
                     webroot: str = WEBROOT) -> tuple[int, bytes]:
        body, ctype = multipart({"cmd": "upload", "target": elfinder_hash("/")},
                                "upload[]", filename, content, content_type)
        return session.request(self.connector_url(project_path, webroot),
                               data=body, headers={"Content-Type": ctype})

    def media_listing(self, session: Session, project_id: int) -> tuple[int, bytes]:
        """The rights-checked per-project media view."""
        return session.form(
            "website_code/php/properties/media_and_quota_template.php",
            {"template_id": project_id})

    def media_url(self, project_path: str, filename: str) -> str:
        return urllib.parse.urljoin(
            self.base, (project_path + "media/" + filename).lstrip("/"))

    def fetch_media(self, project_path: str, filename: str) -> tuple[int, bytes]:
        return public_get(self.base, self.media_url(project_path, filename))
