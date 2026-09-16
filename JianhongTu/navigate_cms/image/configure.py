#!/usr/bin/env python3
"""Render the shipped Navigate setup template without network access."""

from pathlib import Path

source = Path("/srv/challenge/navigate")
template = (source / "cfg/globals.setup.php").read_text(encoding="utf-8")
replacements = {
    "{APP_VERSION}": "2.8 r1302",
    "{APP_OWNER}": "Cyber Arena",
    "{APP_REALM}": "NaviWebs-NaviGate",
    "{APP_UNIQUE}": "ca-navigate-cms",
    "{NAVIGATE_PARENT}": "http://127.0.0.1",
    "{NAVIGATE_FOLDER}": "/navigate",
    "{NAVIGATE_PATH}": "/var/www/html/navigate",
    "{NAVIGATE_PRIVATE}": "/var/www/html/navigate/private",
    "{NAVIGATE_MAIN}": "navigate.php",
    "{NAVIGATECMS_STATS}": "false",
    "{NAVIGATECMS_UPDATES}": "false",
    "{JAVA_RUNTIME}": "java",
    "{PDO_HOSTNAME}": "127.0.0.1",
    "{PDO_PORT}": "3306",
    "{PDO_SOCKET}": "",
    "{PDO_DATABASE}": "navigate",
    "{PDO_USERNAME}": "navigate",
    "{PDO_PASSWORD}": "navigate-db-local",
    "{PDO_DRIVER}": "mysql",
}
for old, new in replacements.items():
    template = template.replace(old, new)
missing = [key for key in replacements if key in template]
if missing:
    raise SystemExit(f"unresolved Navigate placeholders: {missing}")
# The service has several Docker-network names. Keep upstream absolute-URL
# behavior while deriving the authority from the current public request instead
# of redirecting facilities and opponents to their own 127.0.0.1.
template = template.replace(
    "define('NAVIGATE_PARENT', 'http://127.0.0.1');",
    "define('NAVIGATE_PARENT', 'http://'.(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '127.0.0.1'));",
)
(source / "cfg/globals.php").write_text(template, encoding="utf-8")

# Docker's canonical service aliases contain underscores, which are accepted by
# its resolver but invalid in a Cookie Domain attribute. Preserve the same PHP
# session mechanism with host-only cookies, which browsers and stdlib clients
# send back to the exact service authority.
session_path = source / "cfg/session.php"
session_text = session_path.read_text(encoding="utf-8")
session_text = session_text.replace(
    "$session_cookie_domain = $_SERVER['SERVER_NAME'];",
    "$session_cookie_domain = '';",
    1,
).replace(
    "if(!preg_match(\"/^([1-9]",
    "if(false && !preg_match(\"/^([1-9]",
    1,
)
session_path.write_text(session_text, encoding="utf-8")
