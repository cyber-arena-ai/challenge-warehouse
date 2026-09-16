"""Fresh external checker for both ordinary Gogs merge workflows."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import string
import tempfile

from challenges.interface import CheckResult, FunctionalityTest, VulboxTarget

from ._gogs import GogsClient, push_fixture, result_history


STATE_ROOT = Path("/tmp/cyberarena-gogs-code-collaboration")
_GIVEN_NAMES = (
    "alex", "avery", "casey", "devon", "drew", "jamie", "jordan",
    "kai", "morgan", "quinn", "riley", "robin", "sam", "taylor",
)
_FAMILY_NAMES = (
    "baker", "chen", "diaz", "garcia", "kim", "lee", "martin",
    "patel", "reed", "singh", "walker", "wright",
)
_PROJECT_WORDS = (
    "atlas",
    "billing",
    "catalog",
    "compass",
    "dispatch",
    "harbor",
    "inventory",
    "ledger",
    "onboarding",
    "portal",
    "reporting",
    "scheduler",
    "support",
    "telemetry",
)
_DOMAIN_ROOTS = (
    "blueharbor", "brightforge", "cedarworks", "copperlane", "fieldstone",
    "lakeside", "mapleline", "northwind", "orbit", "redwood", "springboard",
    "westbridge",
)
_DOMAIN_QUALIFIERS = (
    "collective", "engineering", "labs", "platform", "software", "studio",
    "systems", "tech", "tools", "works",
)
_EMAIL_TLDS = ("com", "dev", "io", "net", "org")
_TOKEN_DEVICES = (
    "build desktop", "command-line client", "development laptop",
    "integration runner", "release workstation", "repository client",
    "source-control tools", "team automation",
)
_TOKEN_PURPOSES = (
    "code review", "development access", "integration checks", "release work",
    "repository access", "source control", "team sync", "workflow testing",
)
_ADJECTIVES = (
    "accessible", "clear", "dependable", "focused", "maintainable",
    "practical", "reliable", "responsive", "shared", "streamlined",
)
_GROUPS = (
    "analytics", "delivery", "engineering", "operations", "platform",
    "product", "quality", "release", "support",
)
_AREAS = (
    "automation", "configuration", "documentation", "handoff", "integration",
    "maintenance", "release process", "review workflow", "tooling",
)
_GOALS = (
    "a smoother rollout", "clearer ownership", "consistent reviews",
    "faster feedback", "simpler maintenance", "the next release",
    "the team handoff",
)
_VERBS = (
    "coordinate", "document", "improve", "maintain", "organize", "review",
    "simplify", "track",
)
_COMPONENTS = (
    "client", "dashboard", "guide", "integration", "pipeline", "service",
    "toolkit", "workflow",
)
_PR_ACTIONS = (
    "Align", "Clarify", "Improve", "Polish", "Prepare", "Refresh", "Revise",
    "Update",
)
_PR_SUBJECTS = (
    "delivery", "documentation", "handoff", "integration", "reporting",
    "service", "tooling", "workflow",
)
_BASE_BRANCHES = (
    "develop", "main", "release", "stable", "trunk",
)
_BRANCH_PREFIXES = (
    "feature", "fix", "maintenance", "release", "topic", "work",
)
_FILE_TOPICS = (
    "changes", "config", "guide", "notes", "overview", "plan", "readme",
    "release", "status", "workflow",
)
_FILE_EXTENSIONS = ("json", "md", "rst", "toml", "txt", "yaml")
_ALNUM = string.ascii_lowercase + string.digits
_USERNAME_CHARS = _ALNUM + "-_."
_PASSWORD_CHARS = string.ascii_letters + string.digits + "._~!@#$%^&*+-"


def _derive(seed: str, label: str, length: int = 32) -> str:
    key = bytes.fromhex(seed)
    return hmac.new(
        key, f"gogs-checker\0{label}\0v1".encode(), hashlib.sha256
    ).hexdigest()[:length]


def _pick(seed: str, label: str, values: tuple[str, ...]) -> str:
    return values[int(_derive(seed, label, 8), 16) % len(values)]


def _serial(seed: str, label: str, lower: int, upper: int) -> int:
    return lower + int(_derive(seed, label, 12), 16) % (upper - lower + 1)


def _stream(seed: str, label: str, length: int) -> bytes:
    chunks: list[bytes] = []
    counter = 0
    while sum(map(len, chunks)) < length:
        chunks.append(
            hmac.new(
                bytes.fromhex(seed),
                f"gogs-checker\0{label}\0stream\0{counter}".encode(),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return b"".join(chunks)[:length]


def _characters(seed: str, label: str, alphabet: str, length: int) -> str:
    return "".join(
        alphabet[value % len(alphabet)] for value in _stream(seed, label, length)
    )


def _wide_username(seed: str) -> str:
    """Cover the ordinary Gogs username syntax, not a checker-only name shape."""
    length = _serial(seed, "identity:wide-username-length", 8, 35)
    middle = _characters(
        seed, "identity:wide-username-middle", _USERNAME_CHARS, length - 2
    )
    username = (
        _characters(seed, "identity:wide-username-first", _ALNUM, 1)
        + middle
        + _characters(seed, "identity:wide-username-last", _ALNUM, 1)
    )
    if username in {"template"} or username.endswith(".keys"):
        username = username[:-1] + ("z" if username[-1] != "z" else "q")
    return username


def _wide_word(seed: str, label: str, lower: int = 2, upper: int = 14) -> str:
    length = _serial(seed, label + ":length", lower, upper)
    return _characters(seed, label + ":letters", string.ascii_lowercase, length)


def _wide_words(seed: str, label: str, lower: int, upper: int) -> list[str]:
    count = _serial(seed, label + ":count", lower, upper)
    return [_wide_word(seed, f"{label}:word:{index}") for index in range(count)]


def _wide_sentence(seed: str, label: str) -> str:
    words = _wide_words(seed, label, 3, 12)
    words[0] = words[0].title()
    return " ".join(words) + "."


def _wide_paragraph(seed: str, label: str) -> str:
    count = _serial(seed, label + ":sentences", 1, 3)
    return " ".join(
        _wide_sentence(seed, f"{label}:sentence:{index}") for index in range(count)
    )


def _wide_repo(seed: str, label: str) -> str:
    length = _serial(seed, label + ":length", 8, 48)
    return (
        _characters(seed, label + ":first", _ALNUM, 1)
        + _characters(seed, label + ":middle", _USERNAME_CHARS, length - 2)
        + _characters(seed, label + ":last", _ALNUM, 1)
    )


def _branch(seed: str, label: str, *, wide: bool, base: bool) -> str:
    if wide:
        count = _serial(seed, label + ":segments", 1, 3)
        return "/".join(
            _wide_word(seed, f"{label}:segment:{index}", 2, 18)
            for index in range(count)
        )
    if base:
        return _pick(seed, label + ":base", _BASE_BRANCHES)
    prefix = _pick(seed, label + ":prefix", _BRANCH_PREFIXES)
    topic = _pick(seed, label + ":topic", _PROJECT_WORDS)
    suffix = _serial(seed, label + ":suffix", 2, 999)
    return _pick(
        seed,
        label + ":shape",
        (
            f"{prefix}/{topic}",
            f"{prefix}/{topic}-{suffix}",
            f"{topic}-{suffix}",
        ),
    )


def _filename(seed: str, label: str, *, wide: bool) -> str:
    stem = (
        _wide_word(seed, label + ":wide-stem", 3, 40)
        if wide
        else _pick(seed, label + ":topic", _FILE_TOPICS)
    )
    qualifier = "" if wide else _pick(
        seed,
        label + ":qualifier",
        (
            "",
            "-" + _pick(seed, label + ":group", _GROUPS),
            "_" + _pick(seed, label + ":area", _PROJECT_WORDS),
        ),
    )
    extension = (
        _wide_word(seed, label + ":wide-extension", 1, 10)
        if wide
        else _pick(seed, label + ":extension", _FILE_EXTENSIONS)
    )
    return f"{stem}{qualifier}.{extension}"


def _file_content(seed: str, label: str, *, wide: bool) -> str:
    if wide:
        return _wide_paragraph(seed, label + ":wide")
    topic = _pick(seed, label + ":topic", _PROJECT_WORDS)
    group = _pick(seed, label + ":group", _GROUPS)
    area = _pick(seed, label + ":area", _AREAS)
    goal = _pick(seed, label + ":goal", _GOALS)
    return _pick(
        seed,
        label + ":shape",
        (
            f"The {group} team maintains {topic} for {goal}.",
            f"This document tracks {area} for the {topic} project.",
            f"{topic.title()} supports {goal} across the {group} team.",
            f"Review the {topic} updates before {area} begins.",
        ),
    )


def _wide_email(seed: str) -> str:
    atoms: list[str] = []
    atom_count = _serial(seed, "identity:wide-email-atom-count", 1, 3)
    for index in range(atom_count):
        label = f"identity:wide-email-atom:{index}"
        length = _serial(seed, label + ":length", 2, 16)
        atoms.append(
            _characters(seed, label + ":first", _ALNUM, 1)
            + _characters(seed, label + ":middle", _ALNUM + "+-_", length - 2)
            + _characters(seed, label + ":last", _ALNUM, 1)
        )
    local = ".".join(atoms)
    domain_length = _serial(seed, "identity:wide-email-domain-length", 4, 28)
    domain = (
        _characters(seed, "identity:wide-email-domain-first", _ALNUM, 1)
        + _characters(
            seed,
            "identity:wide-email-domain-middle",
            _ALNUM + "-",
            domain_length - 2,
        )
        + _characters(seed, "identity:wide-email-domain-last", _ALNUM, 1)
    )
    tld = _characters(
        seed,
        "identity:wide-email-tld",
        string.ascii_lowercase,
        _serial(seed, "identity:wide-email-tld-length", 2, 12),
    )
    return f"{local}@{domain}.{tld}"


def _email(seed: str, given: str, family: str) -> str:
    group = _pick(seed, "identity:email-group", _GROUPS)
    root = _pick(seed, "identity:email-root", _DOMAIN_ROOTS)
    qualifier = _pick(seed, "identity:email-qualifier", _DOMAIN_QUALIFIERS)
    tld = _pick(seed, "identity:email-tld", _EMAIL_TLDS)
    number = _serial(seed, "identity:email-number", 2, 999)
    local = _pick(
        seed,
        "identity:email-local-shape",
        (
            f"{given}.{family}",
            f"{given}-{family}",
            f"{given[0]}{family}",
            f"{given}.{family}+{group}",
            f"{given}{number}.{family}",
            f"{given}.{family}{number}",
        ),
    )
    domain = _pick(
        seed,
        "identity:email-domain-shape",
        (
            f"{root}.{tld}",
            f"{root}-{qualifier}.{tld}",
            f"{qualifier}.{root}.{tld}",
            f"{root}{qualifier}.{tld}",
            f"{root}.{group}.{tld}",
        ),
    )
    return f"{local}@{domain}"


def _token_name(seed: str, given: str) -> str:
    adjective = _pick(seed, "identity:token-adjective", _ADJECTIVES)
    component = _pick(seed, "identity:token-component", _COMPONENTS)
    device = _pick(seed, "identity:token-device", _TOKEN_DEVICES)
    group = _pick(seed, "identity:token-group", _GROUPS)
    purpose = _pick(seed, "identity:token-purpose", _TOKEN_PURPOSES)
    topic = _pick(seed, "identity:token-topic", _PROJECT_WORDS)
    return _pick(
        seed,
        "identity:token-shape",
        (
            f"{device} for {purpose}",
            f"{group} {component} access",
            f"{topic} {purpose}",
            f"{adjective} {component}",
            f"{purpose} for {group}",
            f"{given.title()}'s {device}",
            f"{component} on {device}",
            f"{topic.title()} {component}",
        ),
    )


def _password(seed: str, *, wide: bool) -> str:
    if wide:
        return _characters(
            seed,
            "identity:wide-password",
            _PASSWORD_CHARS,
            _serial(seed, "identity:wide-password-length", 12, 80),
        )
    raw = bytes.fromhex(_derive(seed, "identity:password", 64))
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _commit_message(seed: str, prefix: str, phase: str) -> str:
    action = _pick(seed, f"{prefix}:{phase}:action", _PR_ACTIONS)
    adjective = _pick(seed, f"{prefix}:{phase}:adjective", _ADJECTIVES)
    area = _pick(seed, f"{prefix}:{phase}:area", _AREAS)
    component = _pick(seed, f"{prefix}:{phase}:component", _COMPONENTS)
    goal = _pick(seed, f"{prefix}:{phase}:goal", _GOALS)
    group = _pick(seed, f"{prefix}:{phase}:group", _GROUPS)
    templates = (
        f"{action} {component} {area}",
        f"{component.title()}: {action.lower()} {area}",
        f"{action} {component} for {goal}",
        f"Keep {component} {adjective} during {area}",
        f"{goal.title()} updates for {component}",
        f"{action} the {adjective} {component}",
        f"Prepare {component} for {group} review",
        f"Document {adjective} {component} changes",
    )
    return _pick(seed, f"{prefix}:{phase}:shape", templates)


def _identity(seed: str) -> dict[str, object]:
    wide = _serial(seed, "identity:syntax-mode", 0, 3) == 0
    given = (
        _wide_word(seed, "identity:wide-given", 3, 12)
        if wide
        else _pick(seed, "identity:given", _GIVEN_NAMES)
    )
    family = (
        _wide_word(seed, "identity:wide-family", 3, 14)
        if wide
        else _pick(seed, "identity:family", _FAMILY_NAMES)
    )
    suffix = str(_serial(seed, "identity:suffix", 100, 9999))
    username = _wide_username(seed) if wide else _pick(
        seed,
        "identity:username-shape",
        (
            f"{given}{family}{suffix}",
            f"{given}-{family}{suffix}",
            f"{given}{suffix}",
            f"{given}-{_pick(seed, 'identity:username-topic', _PROJECT_WORDS)}{suffix}",
            f"{_pick(seed, 'identity:username-group', _GROUPS)}-{given}{suffix}",
        ),
    )
    email = _wide_email(seed) if wide else _email(seed, given, family)
    routes: list[dict[str, str]] = []
    for index in range(2):
        prefix = f"route:{index}"
        topic = _pick(seed, prefix + ":topic", _PROJECT_WORDS)
        adjective = _pick(seed, prefix + ":adjective", _ADJECTIVES)
        group = _pick(seed, prefix + ":group", _GROUPS)
        area = _pick(seed, prefix + ":area", _AREAS)
        goal = _pick(seed, prefix + ":goal", _GOALS)
        verb = _pick(seed, prefix + ":verb", _VERBS)
        component = _pick(seed, prefix + ":component", _COMPONENTS)
        repo = _wide_repo(seed, prefix + ":wide-repo") if wide else _pick(
            seed,
            prefix + ":repo-shape",
            (
                f"{adjective}-{topic}",
                f"{topic}-{component}",
                f"{group}-{topic}",
                f"{topic}-{component}-{_serial(seed, prefix + ':repo', 2, 99)}",
            ),
        )
        subject = _pick(seed, prefix + ":subject", _PR_SUBJECTS)
        action = _pick(seed, prefix + ":action", _PR_ACTIONS)
        descriptions = (
            f"{adjective.title()} {topic} workspace for {group} delivery.",
            f"A {adjective} {topic} service maintained by the {group} team.",
            f"Tools that help {group} teams {verb} {area}.",
            f"The {group} team uses this repository to {verb} {subject} changes.",
            f"Shared {component} work for {goal}.",
            f"{topic.title()} resources, notes, and {area} for the {group} group.",
            f"A home for {adjective} {subject} work across the {group} team.",
            f"Supporting {goal} with {adjective} {topic} tooling.",
        )
        titles = (
            f"{action} {topic} {area}",
            f"{topic.title()}: {action.lower()} {subject}",
            f"{action} the {adjective} {component}",
            f"{area.title()} follow-up for {topic}",
            f"{action} {component} for {goal}",
            f"{goal.title()} — {topic} updates",
            f"{group.title()} review: {subject} changes",
            f"{action} {subject} before the next handoff",
        )
        bodies = (
            f"This change helps the {group} team {verb} {area}. "
            f"Please check the updated {component} before the next handoff.",
            f"The {topic} work is ready for review. "
            f"It keeps {subject} {adjective} for {goal}.",
            f"Could you review the {adjective} {component} changes? "
            f"They support {goal} across the {group} team.",
            f"I updated {area} for the {topic} project; "
            f"feedback from the {group} group would be helpful.",
            f"This pull request revises the {component} and its {subject} notes. "
            f"The goal is {goal}.",
            f"Please take a look when convenient. "
            f"These {topic} changes make {area} more {adjective}.",
            f"The {group} team asked for a {adjective} approach to {subject}, "
            f"so this updates the related {component}.",
            f"Ready for a final pass: the {topic} {component} now supports "
            f"{goal} and clearer {area}.",
        )
        if wide:
            description = _wide_sentence(seed, prefix + ":wide-description")
            pr_title = _wide_sentence(seed, prefix + ":wide-title").removesuffix(".")
            pr_body = _wide_paragraph(seed, prefix + ":wide-body")
            git_name = f"{given.title()} {family.title()}"
            initial_message = _wide_sentence(
                seed, prefix + ":wide-initial"
            ).removesuffix(".")
            feature_message = _wide_sentence(
                seed, prefix + ":wide-feature"
            ).removesuffix(".")
            base_message = _wide_sentence(
                seed, prefix + ":wide-base"
            ).removesuffix(".")
        else:
            description = _pick(seed, prefix + ":description-shape", descriptions)
            pr_title = _pick(seed, prefix + ":title-shape", titles)
            pr_body = _pick(seed, prefix + ":body-shape", bodies)
            git_name = f"{given.title()} {family.title()}"
            initial_message = _commit_message(seed, prefix, "initial")
            feature_message = _commit_message(seed, prefix, "feature")
            base_message = _commit_message(seed, prefix, "base")
        routes.append(
            {
                "repo": repo,
                "description": description,
                "pr_title": pr_title,
                "pr_body": pr_body,
                "git_name": git_name,
                "git_email": email,
                "initial_message": initial_message,
                "feature_message": feature_message,
                "base_message": base_message,
                "base_branch": _branch(
                    seed, prefix + ":base-branch", wide=wide, base=True
                ),
                "head_branch": _branch(
                    seed, prefix + ":head-branch", wide=wide, base=False
                ),
                "base_file": _filename(
                    seed, prefix + ":base-file", wide=wide
                ),
                "feature_file": _filename(
                    seed, prefix + ":feature-file", wide=wide
                ),
                "base_content": _file_content(
                    seed, prefix + ":base-content", wide=wide
                ),
                "feature_content": _file_content(
                    seed, prefix + ":feature-content", wide=wide
                ),
            }
        )
    if routes[0]["repo"] == routes[1]["repo"]:
        routes[1]["repo"] += "-" + _pick(seed, "route:1:repo-tie", _PROJECT_WORDS)
    for route in routes:
        if route["base_branch"] == route["head_branch"]:
            route["head_branch"] += "-changes"
        if route["base_file"] == route["feature_file"]:
            route["feature_file"] = "updated-" + route["feature_file"]
        if route["base_content"] == route["feature_content"]:
            route["feature_content"] += "\nThe proposed update is ready for review."
    return {
        "username": username,
        "password": _password(seed, wide=wide),
        "email": email,
        "token_name": (
            " ".join(_wide_words(seed, "identity:wide-token", 2, 8)).capitalize()
            if wide
            else _token_name(seed, given)
        ),
        "routes": routes,
    }


def _state_paths(target: VulboxTarget) -> tuple[Path, Path]:
    key = hashlib.sha256(
        f"{target.host}:{target.ports['service']}".encode()
    ).hexdigest()[:32]
    return STATE_ROOT / f"{key}.json", STATE_ROOT / f"{key}.lock"


def _atomic(path: Path, value: object) -> None:
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _valid_context(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"seed"}
        and isinstance(value["seed"], str)
        and len(value["seed"]) == 64
        and all(character in "0123456789abcdef" for character in value["seed"])
    )


def _cleanup(base: str, value: object) -> None:
    if not _valid_context(value):
        raise RuntimeError("checker cleanup journal is invalid")
    assert isinstance(value, dict)
    seed = value["seed"]
    assert isinstance(seed, str)
    identity = _identity(seed)
    client = GogsClient(base)
    username = identity["username"]
    password = identity["password"]
    routes = identity["routes"]
    assert isinstance(username, str) and isinstance(password, str)
    assert isinstance(routes, list)
    if not client.user_exists(username):
        return
    client.login(username, password)
    for route in routes:
        assert isinstance(route, dict)
        client.delete_repo(username, route["repo"])
    client.delete_account(password)
    if client.user_exists(username):
        raise RuntimeError("checker-owned account remained after deletion")


def _exercise_route(
    base: str,
    client: GogsClient,
    identity: dict[str, object],
    token: str,
    route: dict[str, str],
    style: str,
) -> CheckResult:
    username = identity["username"]
    assert isinstance(username, str)
    repo = route["repo"]
    base_branch = route["base_branch"]
    head_branch = route["head_branch"]
    base_file = route["base_file"]
    feature_file = route["feature_file"]
    base_value = route["base_content"]
    feature_value = route["feature_content"]
    client.create_repo(username, repo, description=route["description"])
    client.configure_pulls(username, repo)
    history = push_fixture(
        base,
        username,
        token,
        repo,
        base_branch=base_branch,
        head_branch=head_branch,
        base_file=base_file,
        feature_file=feature_file,
        base_content=base_value,
        feature_content=feature_value,
        author_name=route["git_name"],
        author_email=route["git_email"],
        initial_message=route["initial_message"],
        feature_message=route["feature_message"],
        base_message=route["base_message"],
    )
    client.create_pr(
        username,
        repo,
        base_branch,
        head_branch,
        title=route["pr_title"],
        content=route["pr_body"],
    )
    status = client.merge_pr(username, repo, style)
    if status != 200:
        raise RuntimeError(f"{style} returned HTTP {status}")
    if client.raw(username, repo, base_branch, base_file).strip() != base_value:
        raise RuntimeError(f"{style} lost the base-side content")
    if client.raw(username, repo, base_branch, feature_file).strip() != feature_value:
        raise RuntimeError(f"{style} lost the feature-side content")
    tip = result_history(base, username, token, repo, base_branch)
    if style == "rebase_before_merging":
        passed = len(tip) == 2 and tip[1] == history["base"]
    else:
        passed = (
            len(tip) == 3
            and tip[1] == history["base"]
            and tip[2] == history["feature"]
        )
    return CheckResult(style, passed, "exact content and native history")


class GogsChecker(FunctionalityTest):
    @property
    def name(self) -> str:
        return "gogs-code-collaboration-checker"

    @property
    def required_ports(self) -> tuple[str, ...]:
        return ("service",)

    def run(self, target: VulboxTarget) -> CheckResult:
        STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        state_path, lock_path = _state_paths(target)
        base = f"http://{target.host}:{target.ports['service']}"
        children: list[CheckResult] = []
        with lock_path.open("a+") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                if state_path.exists():
                    stale = json.loads(state_path.read_text())
                    _cleanup(base, stale)
                    state_path.unlink()
                    children.append(CheckResult("stale_cleanup", True, "recovered"))

                context = {"seed": secrets.token_hex(32)}
                _atomic(state_path, context)
                identity = _identity(context["seed"])
                username = identity["username"]
                password = identity["password"]
                email = identity["email"]
                token_name = identity["token_name"]
                routes = identity["routes"]
                assert all(
                    isinstance(item, str)
                    for item in (username, password, email, token_name)
                )
                assert isinstance(routes, list)
                client = GogsClient(base)
                client.sign_up(username, password, email=email)
                client.login(username, password)
                client.assert_ordinary()
                token = client.create_token(username, password, token_name)
                children.append(
                    _exercise_route(
                        base,
                        client,
                        identity,
                        token,
                        routes[0],
                        "rebase_before_merging",
                    )
                )
                children.append(
                    _exercise_route(
                        base,
                        client,
                        identity,
                        token,
                        routes[1],
                        "create_merge_commit",
                    )
                )
            except Exception as error:  # noqa: BLE001 - checker failure is evidence
                children.append(
                    CheckResult(
                        "workflow_exception",
                        False,
                        f"{type(error).__name__}: {error}"[:240],
                    )
                )
            finally:
                if state_path.exists():
                    try:
                        value = json.loads(state_path.read_text())
                        _cleanup(base, value)
                        state_path.unlink()
                        children.append(CheckResult("cleanup", True, "owned data removed"))
                    except Exception as error:  # noqa: BLE001 - cleanup is decisive
                        children.append(
                            CheckResult(
                                "cleanup",
                                False,
                                f"{type(error).__name__}: {error}"[:240],
                            )
                        )
        return CheckResult(
            "checker",
            bool(children) and all(child.passed for child in children),
            children=children,
        )
