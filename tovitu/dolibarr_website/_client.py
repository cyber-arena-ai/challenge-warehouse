"""Small standard-library client for the supported Dolibarr Website workflow."""

from __future__ import annotations

import http.cookiejar
import re
import urllib.error
import urllib.parse
import urllib.request


class DolibarrError(RuntimeError):
    """A public workflow did not produce its expected semantic result."""


class Session:
    def __init__(self, base_url: str, *, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar)
        )

    def request(
        self,
        path: str,
        data: dict[str, str] | None = None,
        *,
        referer: str | None = None,
    ) -> tuple[int, str, str]:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        headers = {"User-Agent": "cyber-arena-dolibarr/1"}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if referer:
            headers["Referer"] = self.base_url + referer
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return (
                    response.status,
                    response.read().decode("utf-8", "replace"),
                    response.geturl(),
                )
        except urllib.error.HTTPError as exc:
            return (
                exc.code,
                exc.read().decode("utf-8", "replace"),
                exc.geturl(),
            )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DolibarrError(message)


def csrf_token(body: str) -> str:
    for pattern in (
        r'name="token" value="([a-f0-9]+)"',
        r'name="anti-csrf-newtoken" content="([a-f0-9]+)"',
    ):
        match = re.search(pattern, body)
        if match:
            return match.group(1)
    raise DolibarrError("CSRF token absent")


def login(base_url: str, username: str, password: str) -> tuple[Session, str]:
    session = Session(base_url)
    status, body, _ = session.request("/index.php")
    _require(status == 200, f"login page HTTP {status}")
    token = csrf_token(body)
    status, body, _ = session.request(
        "/index.php?mainmenu=home",
        {
            "token": token,
            "actionlogin": "login",
            "loginfunction": "loginfunction",
            "username": username,
            "password": password,
        },
        referer="/index.php",
    )
    _require(status == 200 and "Logout" in body, "login rejected")
    return session, token


def configure_website(admin: Session, token: str) -> None:
    status, _, _ = admin.request(
        "/admin/company.php",
        {
            "token": token,
            "action": "update",
            "nom": "Cyber Arena",
            "country_id": "11",
            "currency": "USD",
            "save": "Save",
        },
        referer="/admin/company.php?mainmenu=home&action=edit",
    )
    _require(status == 200, f"company configuration HTTP {status}")
    query = urllib.parse.urlencode(
        {
            "id": "10000",
            "token": token,
            "module_position": "50",
            "action": "set",
            "value": "modWebsite",
            "mode": "commonkanban",
        }
    )
    status, body, _ = admin.request(
        "/admin/modules.php?" + query,
        referer="/admin/modules.php?mainmenu=home",
    )
    _require(status == 200 and "Websites" in body, "Website module unavailable")


def _find_user_id(admin: Session, username: str) -> int | None:
    query = urllib.parse.urlencode({"search_login": username})
    status, body, _ = admin.request("/user/list.php?" + query)
    _require(status == 200, f"user lookup HTTP {status}")
    for match in re.finditer(r"user/card\.php\?id=(\d+)", body):
        start = max(0, match.start() - 250)
        end = min(len(body), match.end() + 600)
        if username in body[start:end]:
            return int(match.group(1))
    return None


def ensure_editor(
    admin: Session,
    token: str,
    username: str,
    password: str,
    label: str,
) -> int:
    user_id = _find_user_id(admin, username)
    if user_id is None:
        status, _, final_url = admin.request(
            "/user/card.php",
            {
                "token": token,
                "action": "add",
                "entity": "1",
                "lastname": label,
                "firstname": "Arena",
                "login": username,
                "admin": "0",
                "gender": "-1",
                "employee": "1",
                "fk_user": "-1",
                "password": password,
                "save": "Create user",
            },
            referer="/user/card.php?leftmenu=users&action=create",
        )
        _require(status == 200, f"user creation HTTP {status}")
        match = re.search(r"[?&]id=(\d+)", final_url)
        user_id = int(match.group(1)) if match else _find_user_id(admin, username)
        _require(user_id is not None, "created user id absent")

    for right in (10001, 10002):
        query = urllib.parse.urlencode(
            {
                "id": str(user_id),
                "action": "addrights",
                "entity": "1",
                "rights": str(right),
                "confirm": "yes",
                "token": token,
            }
        )
        status, _, _ = admin.request(
            "/user/perms.php?" + query,
            referer=f"/user/perms.php?id={user_id}",
        )
        _require(status == 200, f"permission {right} HTTP {status}")

    status, body, _ = admin.request(f"/user/perms.php?id={user_id}")
    _require(status == 200, f"permission verification HTTP {status}")
    for right in (10001, 10002):
        row = re.search(rf"rights={right}.*?</tr>", body, re.DOTALL)
        _require(row is not None and "toggle-on" in row.group(0), f"right {right} absent")
    php_row = re.search(r"rights=10003.*?</tr>", body, re.DOTALL)
    _require(
        php_row is not None and "toggle-off" in php_row.group(0),
        "dynamic-PHP right was not withheld",
    )
    return user_id


def create_site_and_page(
    editor: Session, token: str, site_ref: str, page_ref: str
) -> int:
    status, _, _ = editor.request(
        "/website/index.php",
        {
            "token": token,
            "action": "addsite",
            "website": "-1",
            "WEBSITE_REF": site_ref,
            "WEBSITE_LANG": "en",
            "addcontainer": "Create",
        },
        referer="/website/index.php",
    )
    _require(status == 200, f"site creation HTTP {status}")
    status, body, _ = editor.request(
        "/website/index.php",
        {
            "token": token,
            "action": "addcontainer",
            "website": site_ref,
            "radiocreatefrom": "checkboxcreatemanually",
            "WEBSITE_TYPE_CONTAINER": "page",
            "sample": "empty",
            "WEBSITE_TITLE": page_ref,
            "WEBSITE_PAGENAME": page_ref,
            "WEBSITE_LANG": "en",
            "addcontainer": "Create",
        },
        referer=f"/website/index.php?website={site_ref}",
    )
    _require(status == 200, f"page creation HTTP {status}")
    match = re.search(r'<option value="(\d+)" selected', body)
    _require(match is not None, "created page id absent")
    return int(match.group(1))


def update_page(
    editor: Session,
    token: str,
    site_ref: str,
    page_id: int,
    content: str,
) -> str:
    status, body, _ = editor.request(
        "/website/index.php",
        {
            "token": token,
            "backtopage": "",
            "dol_openinpopup": "",
            "action": "updatesource",
            "website": site_ref,
            "pageid": str(page_id),
            "update": "Save",
            "PAGE_CONTENT": content,
        },
        referer=f"/website/index.php?website={site_ref}&pageid={page_id}",
    )
    _require(status == 200, f"page update HTTP {status}")
    return body


def render_public(base_url: str, site_ref: str, page_ref: str) -> str:
    query = urllib.parse.urlencode({"website": site_ref, "pageref": page_ref})
    status, body, _ = Session(base_url).request("/public/website/index.php?" + query)
    _require(status == 200, f"public render HTTP {status}")
    return body
