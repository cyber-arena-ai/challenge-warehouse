#!/usr/bin/env python3
"""Root-only application administration for objectives and health noise."""

from __future__ import annotations

import base64
import json
from pathlib import Path
import re
import subprocess
import sys


PRIVATE = Path("/var/lib/cyberarena")
OBJECTIVE = PRIVATE / "wordpress-objective.json"
OBJECTIVE_ISSUED = PRIVATE / "wordpress-objective-issued"
NOISE = PRIVATE / "wordpress-health.json"
NOISE_ISSUED = PRIVATE / "wordpress-health-issued"
OPTION = re.compile(r"site_private_[0-9a-f]{24}")
CONTEXT = re.compile(r"[0-9a-f]{64}")
SLUG = re.compile(r"[a-z][a-z0-9-]{7,79}")
ISSUED = "wordpress-objective-v1\n"
OBJECTIVE_SENTINEL = "site_installation_generation"
OBJECTIVE_SENTINEL_VALUE = "protected-settings-v1"


def decode(raw: str) -> object:
    try:
        return json.loads(base64.b64decode(raw, validate=True))
    except (ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid facility request") from error


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".next")
    temporary.write_text(json.dumps(value, separators=(",", ":"), sort_keys=True))
    temporary.chmod(0o600)
    temporary.replace(path)


def mark(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".next")
    temporary.write_text(value)
    temporary.chmod(0o600)
    temporary.replace(path)


def wp_eval(code: str) -> str:
    completed = subprocess.run(
        [
            "runuser",
            "-u",
            "www-data",
            "--",
            "/usr/local/bin/wp",
            "--path=/var/www/html",
            "--skip-plugins",
            "--skip-themes",
            "eval",
            code,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("WordPress application operation failed")
    return completed.stdout


def php_string(value: str) -> str:
    return f'base64_decode("{base64.b64encode(value.encode()).decode()}")'


def option_read(target: str) -> str | None:
    sentinel = "__cyberarena_missing_" + "0" * 24
    code = (
        f"$v=get_option({php_string(target)},{php_string(sentinel)});"
        f"if($v==={php_string(sentinel)}){{exit(4);}}"
        "if(!is_string($v)){exit(5);}echo $v;"
    )
    completed = subprocess.run(
        [
            "runuser", "-u", "www-data", "--", "/usr/local/bin/wp",
            "--path=/var/www/html", "--skip-plugins", "--skip-themes",
            "eval", code,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode == 4:
        return None
    if completed.returncode != 0:
        raise RuntimeError("WordPress protected setting read failed")
    return completed.stdout


def option_write(target: str, value: str) -> None:
    code = (
        f"$n={php_string(target)};$v={php_string(value)};"
        "update_option($n,$v,false);"
        "if(get_option($n,null)!==$v){exit(6);}echo 'OK';"
    )
    if wp_eval(code).strip() != "OK":
        raise RuntimeError("WordPress protected setting verification failed")


def option_add(target: str, value: str) -> None:
    code = (
        f"$n={php_string(target)};$v={php_string(value)};"
        "$old=get_option($n,null);"
        "if($old===null){if(!add_option($n,$v,'','no')){exit(6);}$old=get_option($n,null);}"
        "if($old!==$v){exit(7);}echo 'OK';"
    )
    if wp_eval(code).strip() != "OK":
        raise RuntimeError("WordPress issuance sentinel is invalid")


def option_delete(target: str) -> None:
    code = (
        f"$n={php_string(target)};delete_option($n);"
        "if(get_option($n,null)!==null){exit(6);}echo 'OK';"
    )
    if wp_eval(code).strip() != "OK":
        raise RuntimeError("WordPress protected setting cleanup failed")


def site_owner_id() -> int:
    value = wp_eval(
        "$u=get_user_by('login','site-owner');if(!$u){exit(6);}echo $u->ID;"
    ).strip()
    if not value.isdigit() or int(value) < 1:
        raise RuntimeError("WordPress site owner is unavailable")
    return int(value)


def objective_entry(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"context", "target", "value"}
        and isinstance(value.get("context"), str)
        and CONTEXT.fullmatch(value["context"]) is not None
        and isinstance(value.get("target"), str)
        and OPTION.fullmatch(value["target"]) is not None
        and isinstance(value.get("value"), str)
        and bool(value["value"])
    )


def load_objective() -> dict[str, object]:
    marker = OBJECTIVE_ISSUED.exists()
    if marker and (
        not OBJECTIVE_ISSUED.is_file() or OBJECTIVE_ISSUED.read_text() != ISSUED
    ):
        raise RuntimeError("objective issuance marker is malformed")
    sentinel = option_read(OBJECTIVE_SENTINEL)
    if sentinel not in (None, OBJECTIVE_SENTINEL_VALUE):
        raise RuntimeError("objective issuance sentinel is malformed")
    if not OBJECTIVE.exists():
        if marker or sentinel is not None:
            raise RuntimeError("objective journal is missing after issuance")
        return {"v": 1, "current": None, "previous": None, "pending": None}
    try:
        value = json.loads(OBJECTIVE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("objective journal is malformed") from error
    entries = [value.get(slot) for slot in ("current", "previous", "pending")] if isinstance(value, dict) else []
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "current", "previous", "pending"}
        or value.get("v") != 1
        or any(entry is not None and not objective_entry(entry) for entry in entries)
        or not any(entry is not None for entry in entries)
    ):
        raise RuntimeError("objective journal is malformed")
    targets = [entry["target"] for entry in entries if isinstance(entry, dict)]
    if len(targets) != len(set(targets)):
        raise RuntimeError("objective journal is malformed")
    first_issuance_pending = (
        value["current"] is None
        and value["previous"] is None
        and value["pending"] is not None
    )
    if not first_issuance_pending and (
        not marker or sentinel != OBJECTIVE_SENTINEL_VALUE
    ):
        raise RuntimeError("objective issuance state is incomplete")
    return value


def plant(request: object) -> None:
    if not objective_entry(request):
        raise RuntimeError("invalid objective request")
    assert isinstance(request, dict)
    journal = load_objective()
    current = journal["current"]
    previous = journal["previous"]
    if previous is not None and current != request:
        assert isinstance(previous, dict)
        option_delete(previous["target"])
        journal["previous"] = None
        write_json(OBJECTIVE, journal)

    pending = journal["pending"]
    if pending is not None and pending != request:
        assert isinstance(pending, dict)
        option_delete(pending["target"])
        journal["pending"] = None
        write_json(OBJECTIVE, journal)

    if isinstance(current, dict) and current.get("target") == request["target"] and current != request:
        raise RuntimeError("round context was reused with different proof state")

    if current != request:
        journal["pending"] = request
        write_json(OBJECTIVE, journal)

    if current is None and journal["previous"] is None:
        option_add(OBJECTIVE_SENTINEL, OBJECTIVE_SENTINEL_VALUE)
        mark(OBJECTIVE_ISSUED, ISSUED)

    option_write(request["target"], request["value"])
    if option_read(request["target"]) != request["value"]:
        raise RuntimeError("staged objective verification failed")

    if current != request:
        write_json(
            OBJECTIVE,
            {"v": 1, "current": request, "previous": current, "pending": None},
        )
    print("OK")


def noise_entry(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "app_id",
            "client_name",
            "lease",
            "slug",
            "title",
            "content",
            "decoy_slug",
            "decoy_title",
            "decoy_content",
            "batch_title",
            "batch_content",
            "decoy_batch_title",
            "decoy_batch_content",
        }
        and isinstance(value.get("app_id"), str)
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value["app_id"],
        )
        is not None
        and isinstance(value.get("client_name"), str)
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9 ]{7,79}", value["client_name"])
        is not None
        and isinstance(value.get("lease"), str)
        and re.fullmatch(r"[0-9a-f]{32}", value["lease"]) is not None
        and isinstance(value.get("slug"), str)
        and SLUG.fullmatch(value["slug"]) is not None
        and isinstance(value.get("decoy_slug"), str)
        and SLUG.fullmatch(value["decoy_slug"]) is not None
        and value["slug"] != value["decoy_slug"]
        and all(
            isinstance(value.get(field), str) and bool(value[field])
            for field in ("title", "content", "decoy_title", "decoy_content")
        )
        and all(
            isinstance(value.get(field), str) and bool(value[field])
            for field in (
                "batch_title",
                "batch_content",
                "decoy_batch_title",
                "decoy_batch_content",
            )
        )
    )


def owned_noise(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"lease", "slug", "decoy_slug", "app_id"}
        and isinstance(value.get("lease"), str)
        and re.fullmatch(r"[0-9a-f]{32}", value["lease"]) is not None
        and isinstance(value.get("slug"), str)
        and SLUG.fullmatch(value["slug"]) is not None
        and isinstance(value.get("decoy_slug"), str)
        and SLUG.fullmatch(value["decoy_slug"]) is not None
        and isinstance(value.get("app_id"), str)
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
            value["app_id"],
        )
        is not None
    )


def noise_record(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"owned"}
        and owned_noise(value.get("owned"))
    )


def load_noise() -> dict[str, object]:
    if NOISE_ISSUED.exists() and (
        not NOISE_ISSUED.is_file()
        or NOISE_ISSUED.read_text() != "wordpress-health-v1\n"
    ):
        raise RuntimeError("health issuance marker is malformed")
    if not NOISE.exists():
        if NOISE_ISSUED.exists():
            raise RuntimeError("health journal is missing after issuance")
        return {"v": 1, "current": None, "pending": None}
    try:
        value = json.loads(NOISE.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("health journal is malformed") from error
    entries = [value.get(slot) for slot in ("current", "pending")] if isinstance(value, dict) else []
    if (
        not isinstance(value, dict)
        or set(value) != {"v", "current", "pending"}
        or value.get("v") != 1
        or any(entry is not None and not noise_record(entry) for entry in entries)
    ):
        raise RuntimeError("health journal is malformed")
    return value


def delete_post(slug: str) -> None:
    code = (
        f"$s={php_string(slug)};$rows=get_posts(array('name'=>$s,'post_type'=>'post',"
        "'post_status'=>'any','numberposts'=>-1));"
        "foreach($rows as $row){if(wp_delete_post($row->ID,true)===false){exit(6);}}echo 'OK';"
    )
    if wp_eval(code).strip() != "OK":
        raise RuntimeError("health post cleanup failed")


def upsert_post(entry: dict[str, str], author_id: int) -> int:
    code = (
        f"$s={php_string(entry['slug'])};$t={php_string(entry['title'])};"
        f"$c={php_string(entry['content'])};"
        "$rows=get_posts(array('name'=>$s,'post_type'=>'post','post_status'=>'any','numberposts'=>-1));"
        "$id=count($rows)?$rows[0]->ID:0;"
        "$id=wp_insert_post(array('ID'=>$id,'post_name'=>$s,'post_title'=>$t,"
        f"'post_content'=>$c,'post_status'=>'publish','post_type'=>'post','post_author'=>{author_id}),true);"
        "if(is_wp_error($id)){exit(6);}echo $id;"
    )
    value = wp_eval(code).strip()
    if not value.isdigit() or int(value) < 1:
        raise RuntimeError("health post placement failed")
    return int(value)


def delete_app_password(app_id: str) -> None:
    code = (
        f"$a={php_string(app_id)};$u=get_user_by('login','site-owner');"
        "if(!$u){exit(6);}"
        "$rows=WP_Application_Passwords::get_user_application_passwords($u->ID);"
        "foreach($rows as $row){if(isset($row['app_id'])&&$row['app_id']===$a){"
        "if(!WP_Application_Passwords::delete_application_password("
        "$u->ID,$row['uuid'])){exit(7);}}}"
        "$rows=WP_Application_Passwords::get_user_application_passwords($u->ID);"
        "foreach($rows as $row){if(isset($row['app_id'])&&$row['app_id']===$a){exit(8);}}"
        "echo 'OK';"
    )
    if wp_eval(code).strip() != "OK":
        raise RuntimeError("health credential cleanup failed")


def issue_app_password(app_id: str, client_name: str) -> str:
    delete_app_password(app_id)
    code = (
        f"$a={php_string(app_id)};$n={php_string(client_name)};"
        "$u=get_user_by('login','site-owner');if(!$u){exit(6);}"
        "$r=WP_Application_Passwords::create_new_application_password("
        "$u->ID,array('name'=>$n,'app_id'=>$a));"
        "if(is_wp_error($r)){exit(7);}echo $r[0];"
    )
    password = wp_eval(code).strip()
    if not password:
        raise RuntimeError("health credential issuance failed")
    return password


def cleanup_noise(record: dict[str, object]) -> None:
    owned = record["owned"]
    assert isinstance(owned, dict)
    delete_post(owned["slug"])
    delete_post(owned["decoy_slug"])
    delete_app_password(owned["app_id"])


def health_noise(request: object) -> None:
    if not noise_entry(request):
        raise RuntimeError("invalid health-noise request")
    assert isinstance(request, dict)
    journal = load_noise()
    seen: set[str] = set()
    for slot in ("current", "pending"):
        record = journal[slot]
        if record is not None:
            assert isinstance(record, dict)
            owned = record["owned"]
            assert isinstance(owned, dict)
            if owned["lease"] not in seen:
                cleanup_noise(record)
                seen.add(owned["lease"])
    write_json(NOISE, {"v": 1, "current": None, "pending": None})
    mark(NOISE_ISSUED, "wordpress-health-v1\n")

    owned = {field: request[field] for field in ("lease", "slug", "decoy_slug")}
    owned["app_id"] = request["app_id"]
    record = {"owned": owned}
    journal = {"v": 1, "current": None, "pending": record}
    write_json(NOISE, journal)
    author_id = site_owner_id()
    post_id = upsert_post(request, author_id)
    decoy = {
        "slug": request["decoy_slug"],
        "title": request["decoy_title"],
        "content": request["decoy_content"],
    }
    missing_post_id = upsert_post(decoy, author_id)
    delete_post(request["decoy_slug"])
    decoy_post_id = upsert_post(decoy, author_id)
    if missing_post_id == decoy_post_id:
        raise RuntimeError("health post tombstone was reused")
    password = issue_app_password(owned["app_id"], request["client_name"])
    write_json(NOISE, {"v": 1, "current": record, "pending": None})
    print(
        json.dumps(
            {
                "noise": request,
                "auth": {"username": "site-owner", "password": password},
                "missing_post_id": missing_post_id,
                "posts": [
                    {"id": post_id, "slug": request["slug"]},
                    {
                        "id": decoy_post_id,
                        "slug": request["decoy_slug"],
                    },
                ],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def health_cleanup(request: object) -> None:
    lease = request.get("lease") if isinstance(request, dict) else None
    if not isinstance(lease, str) or re.fullmatch(r"[0-9a-f]{32}", lease) is None:
        raise RuntimeError("invalid health cleanup request")
    journal = load_noise()
    current = journal["current"]
    if not isinstance(current, dict):
        raise RuntimeError("health cleanup has no owned records")
    owned = current["owned"]
    if not isinstance(owned, dict) or owned.get("lease") != lease:
        raise RuntimeError("health cleanup ownership mismatch")
    cleanup_noise(current)
    write_json(NOISE, {"v": 1, "current": None, "pending": None})
    print("OK")


def read(request: object) -> None:
    target = request.get("target") if isinstance(request, dict) else None
    if not isinstance(target, str) or OPTION.fullmatch(target) is None:
        raise RuntimeError("invalid objective target")
    value = option_read(target)
    if value is None:
        raise SystemExit(4)
    sys.stdout.write(value + "\n")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(2)
    operation = sys.argv[1]
    request = decode(sys.argv[2])
    if operation == "plant":
        plant(request)
    elif operation == "read":
        read(request)
    elif operation == "health-noise":
        health_noise(request)
    elif operation == "health-cleanup":
        health_cleanup(request)
    else:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
