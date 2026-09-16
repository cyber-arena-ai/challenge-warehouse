from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from challenges.interface import Flag, ObservationStatus, OracleKind, VulboxTarget
from challenges.dolibarr_website import DolibarrWebsiteChallenge
from challenges.dolibarr_website import _exploit
from challenges.dolibarr_website import build as build_module
from challenges.dolibarr_website import checker as checker_module
from challenges.dolibarr_website import flag_handler as flag_handler_module
from challenges.dolibarr_website import _client as client_module
from challenges.dolibarr_website.checker import DolibarrWebsiteChecker
from challenges.dolibarr_website.checker_identity import (
    COHORT_PATH,
    seal_issued_cohort,
)
from challenges.dolibarr_website.flag_handler import STORE


ROUND_SEED = "01" * 32


COHORT_USER = "ed" + "c" * 14
COHORT_PASSWORD = "Aa1!" + "c" * 32


def cohort_target(monkeypatch, **kwargs):
    """A target whose exec bridge serves one sealed issued editor."""
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    sealed = seal_issued_cohort([[COHORT_USER, COHORT_PASSWORD]])
    return target(lambda *_args: (0, sealed), **kwargs)


def target(exec_in, *, team_id="team1", round_seed=ROUND_SEED):
    return VulboxTarget(
        host="team1_prod",
        ports={"service": 80},
        meta={
            "team_id": team_id,
            "exec_in_container": exec_in,
            "round_context_seed": round_seed,
        },
    )


def test_composition_declares_one_scoped_execute_store():
    challenge = DolibarrWebsiteChallenge()
    specs = challenge.flag_store_specs()
    assert [(spec.name, spec.kind, spec.scope) for spec in specs] == [
        (STORE, OracleKind.EXECUTE, "host.command.execute")
    ]
    assert challenge.vulbox.exposed_ports == {"service": 80}


def test_plant_exposes_only_service_operation_parent(monkeypatch):
    operation_id = flag_handler_module._round_value(
        target(lambda *_args: (0, "")), "operation-id", 32
    )
    calls = []
    monkeypatch.setattr(
        flag_handler_module,
        "_persist_operation_id",
        lambda _target, derived, _key: derived,
    )

    def execute(host, command):
        calls.append((host, command))
        return 0, operation_id

    handler = DolibarrWebsiteChallenge().flag_handler
    handle = handler.plant(target(execute), {STORE: Flag("FLAG{unit_test_value}")})[STORE]
    assert handler.flag_id(handle) == f"/usr/local/libexec/dolibarr-proof {operation_id}"
    assert "-m 711 /var/lib/cyberarena/dolibarr-proof" in calls[0][1]
    assert "-m 700 /var/lib/cyberarena/dolibarr-proof/tokens" in calls[0][1]


def test_same_round_retry_reconstructs_exact_state_and_preserves_valid_id(monkeypatch):
    operation_id = flag_handler_module._round_value(
        target(lambda *_args: (0, "")), "operation-id", 32
    )
    calls = []

    monkeypatch.setattr(
        flag_handler_module,
        "_persist_operation_id",
        lambda _target, derived, _key: derived,
    )

    def execute(_host, command):
        calls.append(command)
        return 0, operation_id

    handler = DolibarrWebsiteChallenge().flag_handler
    handle = handler.plant(target(execute), {STORE: Flag("FLAG{same_round}")})[STORE]

    assert handler.flag_id(handle) == f"/usr/local/libexec/dolibarr-proof {operation_id}"
    converge = calls[0]
    assert "rm -rf /var/lib/cyberarena/dolibarr-proof/operations" in converge
    assert f"tokens/{operation_id}" in converge
    assert "chown root:root" in converge
    assert "chmod 600" in converge
    assert "current.id" in converge and "current.flag" in converge


def test_round_context_is_stable_separated_rotating_and_proof_independent():
    first = target(lambda *_args: (0, ""), round_seed="11" * 32)
    retry = target(lambda *_args: (0, ""), round_seed="11" * 32)
    rotated = target(lambda *_args: (0, ""), round_seed="12" * 32)

    first_operation = flag_handler_module._round_value(first, "operation-id", 32)
    assert first_operation == flag_handler_module._round_value(
        retry, "operation-id", 32
    )
    assert first_operation != flag_handler_module._round_value(
        rotated, "operation-id", 32
    )
    assert first_operation != flag_handler_module._round_value(
        first, "placement-cache", 32
    )


def test_operation_context_does_not_depend_on_proof_value(monkeypatch):
    monkeypatch.setattr(
        flag_handler_module,
        "_persist_operation_id",
        lambda _target, operation, _key: operation,
    )
    first = target(lambda *_args: (0, ""), round_seed="21" * 32)
    rotated = target(lambda *_args: (0, ""), round_seed="22" * 32)

    assert flag_handler_module._preallocate_operation_id(
        first
    ) == flag_handler_module._preallocate_operation_id(
        first
    )
    assert flag_handler_module._preallocate_operation_id(
        first
    ) != flag_handler_module._preallocate_operation_id(
        rotated
    )


def test_cached_operation_must_match_seed_derived_target(monkeypatch):
    monkeypatch.setattr(
        flag_handler_module,
        "_persist_operation_id",
        lambda *_args: "f" * 32,
    )
    with pytest.raises(RuntimeError, match="cached execution proof locator is invalid"):
        flag_handler_module._preallocate_operation_id(
            target(lambda *_args: (0, ""))
        )


def test_round_context_seed_is_required():
    without_seed = VulboxTarget(
        host="team1_prod",
        ports={"service": 80},
        meta={"team_id": "team1", "exec_in_container": lambda *_args: (0, "")},
    )
    try:
        flag_handler_module._round_value(without_seed, "operation-id", 32)
    except RuntimeError as error:
        assert str(error) == "round context seed unavailable"
    else:
        raise AssertionError("missing round context seed must fail closed")


def test_build_rebuilds_current_context_when_tag_exists(monkeypatch):
    class ExistingImages:
        def get(self, _tag):
            return object()

    class ExistingImageClient:
        images = ExistingImages()

    calls = []
    monkeypatch.setattr(
        build_module.subprocess,
        "run",
        lambda command, **kwargs: (
            calls.append((command, kwargs))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )

    tag = build_module.build_image(ExistingImageClient())

    assert tag == "cyberarena/chal-dolibarr-website:v1"
    assert calls == [
        (
            [
                "docker",
                "build",
                "--platform=linux/amd64",
                "--pull=false",
                "-t",
                tag,
                str(build_module._CONTEXT),
            ],
            {"check": False, "capture_output": True, "text": True},
        )
    ]


def test_runtime_sync_deploys_complete_editable_htdocs_tree():
    image = build_module._CONTEXT
    entrypoint = (image / "entrypoint.sh").read_text()
    restart = (image / "restart.sh").read_text()

    assert "--exclude custom/" not in entrypoint
    assert "--exclude custom/" not in restart
    assert "rsync -a --delete /srv/challenge/dolibarr/htdocs/ /var/www/html/" in entrypoint
    assert 'rsync -a --delete "$SOURCE/htdocs/" "$LIVE/"' in restart


def test_restart_forces_stale_apache_to_die_before_source_replacement():
    restart = (build_module._CONTEXT / "restart.sh").read_text()

    live_process_filter = restart.index("ps -C apache2 -o stat=")
    graceful = restart.index("pkill -TERM -x apache2")
    forced = restart.index("pkill -KILL -x apache2")
    death_assertion = restart.index('echo "Apache processes survived shutdown"')
    stop_call = restart.index('\nstop_apache\ntest -f "$SOURCE/htdocs/index.php"')
    source_validation = restart.index('test -f "$SOURCE/htdocs/index.php"')
    source_replacement = restart.index('rsync -a --delete "$SOURCE/htdocs/" "$LIVE/"')
    cleanup_trap = restart.index("trap cleanup_failed_restart EXIT")
    replacement_start = restart.index("apache2ctl start")
    assert live_process_filter < graceful < forced < death_assertion < stop_call
    assert stop_call < source_validation < source_replacement < cleanup_trap
    assert cleanup_trap < replacement_start
    assert "[^Z[:space:]]" in restart
    assert "pgrep -x apache2" not in restart


def test_restart_cleans_up_a_replacement_that_never_becomes_ready():
    restart = (build_module._CONTEXT / "restart.sh").read_text()

    cleanup = restart[restart.index("cleanup_failed_restart()") :]
    assert "stop_apache || true" in cleanup
    assert "trap - EXIT" in cleanup
    assert cleanup.index("trap cleanup_failed_restart EXIT") < cleanup.index(
        "apache2ctl start"
    )
    readiness = cleanup[cleanup.index("for _ in $(seq 1 60)") :]
    assert readiness.index("trap - EXIT") < readiness.index("exit 0")
    assert readiness.rstrip().endswith("exit 1")


def test_public_client_sends_randomized_browser_identity_without_checker_fingerprint(
    monkeypatch,
):
    choices = iter(("X11; Linux x86_64", "chrome"))
    numbers = iter((5, 17, 23))
    monkeypatch.setattr(client_module.secrets, "choice", lambda _values: next(choices))
    monkeypatch.setattr(client_module.secrets, "randbelow", lambda _limit: next(numbers))

    seen = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b"ok"

        def geturl(self):
            return "http://dolibarr.test/index.php"

    class Opener:
        def open(self, request, *, timeout):
            seen["user_agent"] = request.get_header("User-agent")
            seen["timeout"] = timeout
            return Response()

    monkeypatch.setattr(client_module.urllib.request, "build_opener", lambda *_args: Opener())
    session = client_module.Session("http://dolibarr.test")
    status, body, _ = session.request("/index.php")

    assert (status, body) == (200, "ok")
    assert seen == {
        "user_agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.6417.23 Safari/537.36"
        ),
        "timeout": 20.0,
    }
    assert "cyber-arena" not in seen["user_agent"].lower()


def test_retrieve_runs_operation_as_www_data():
    operation_id = "b" * 32
    flag = "FLAG{unit_test_value}"
    handle = json.dumps(
        {
            "flag_id": "/usr/local/libexec/dolibarr-proof " + operation_id,
            "flag": flag,
        }
    )
    calls = []

    def execute(host, command):
        calls.append((host, command))
        return 0, flag + "\n"

    observation = DolibarrWebsiteChallenge().flag_handler.retrieve(
        target(execute), handle, expected=flag
    )
    assert observation.status is ObservationStatus.PRESENT
    assert calls == [
        (
            "team1_prod",
            "su -s /bin/sh www-data -c "
            + repr("/usr/local/libexec/dolibarr-proof " + operation_id),
        )
    ]


def test_liveness_returns_red_when_http_is_down():
    result = DolibarrWebsiteChallenge().functionality_test.run(
        target(lambda _host, _command: (7, ""))
    )
    assert result.passed is False


def test_checker_reads_the_sealed_cohort_then_works_over_http(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    issued = [
        ["ed" + "c" * 14, "Aa1!" + "c" * 32],
        ["ed" + "d" * 14, "Aa1!" + "d" * 32],
    ]
    sealed = seal_issued_cohort(issued)
    exec_calls = []
    calls = []

    def login(base_url, username, password):
        calls.append((base_url, username, password))
        return object(), "token"

    monkeypatch.setattr(checker_module, "login", login)
    references = iter(
        (
            "Coastal_design482",
            "Guided-design731",
            "Harbour_survey905",
            "Tidal-register117",
        )
    )
    monkeypatch.setattr(
        checker_module,
        "_reference",
        lambda: next(references),
    )
    expected_content = (
        "<main data-topic=\"coast\"><article><h2>Coastal guide</h2></article>"
        "<script>const guide='fresh';</script></main>"
    )
    monkeypatch.setattr(
        checker_module, "_publication_document", lambda: expected_content
    )
    published: list[tuple[str, str]] = []
    updated: list[tuple[str, str]] = []
    monkeypatch.setattr(
        checker_module,
        "create_site_and_page",
        lambda _editor, _token, site, page: published.append((site, page)) or 17,
    )
    monkeypatch.setattr(
        checker_module,
        "update_page",
        lambda _editor, _token, site, page_id, content: updated.append(
            (site, content)
        ),
    )
    monkeypatch.setattr(
        checker_module,
        "render_public",
        lambda *_args: f"<body>{expected_content}</body>",
    )
    def exec_in(host, command):
        exec_calls.append((host, command))
        return 0, sealed

    result = DolibarrWebsiteChecker().run(target(exec_in))
    assert result.passed is True
    assert exec_calls == [("team1_prod", f"cat {COHORT_PATH}")]
    # every issued editor is exercised, each with its own fresh site and page
    assert calls == [
        ("http://team1_prod:80", username, password) for username, password in issued
    ]
    assert published == [
        ("Coastal_design482", "Guided-design731"),
        ("Harbour_survey905", "Tidal-register117"),
    ]
    assert updated == [
        ("Coastal_design482", expected_content),
        ("Harbour_survey905", expected_content),
    ]
    assert "arena" not in expected_content.lower()
    assert "dolibarr" not in expected_content.lower()


def test_expected_rendering_matches_the_measured_native_media_rewrite():
    # Measured against cyberarena/chal-dolibarr-website:v1 (Dolibarr 16.0.5):
    # a colon anywhere leaves the source alone; otherwise the renderer prefixes
    # /viewimage.php and strips one leading slash.
    rewrite = checker_module._expected_rendering
    assert rewrite('<img src="assets/plain" alt="a" />') == (
        '<img src="/viewimage.php?modulepart=medias&file=assets/plain" alt="a" />'
    )
    assert rewrite('<img src="/root/x" alt="a" />') == (
        '<img src="/viewimage.php?modulepart=medias&file=root/x" alt="a" />'
    )
    assert rewrite('<img src="assets/a:b" alt="a" />') == (
        '<img src="assets/a:b" alt="a" />'
    )
    assert rewrite('<img src="assets/a!b" alt="a" />') == (
        '<img src="assets/a!b" alt="a" />'
    )
    assert rewrite('<img src="" alt="a" />') == '<img src="" alt="a" />'
    # the renderer keys on any tag whose name starts with img, and takes the
    # last src in the tag
    assert rewrite('<imgi src="assets/x" alt="a" />') == (
        '<imgi src="/viewimage.php?modulepart=medias&file=assets/x" alt="a" />'
    )
    assert rewrite('<img src="assets/a" data-y="1" src="assets/b" />') == (
        '<img src="assets/a" data-y="1"'
        ' src="/viewimage.php?modulepart=medias&file=assets/b" />'
    )
    assert rewrite('<img src="medias/x" alt="a" />') == (
        '<img src="/viewimage.php?modulepart=medias&file=x" alt="a" />'
    )
    assert rewrite('<img src="viewimage.php?x=1" alt="a" />') == (
        '<img src="/viewimage.php?x=1" alt="a" />'
    )
    assert rewrite("<p>no image here</p>") == "<p>no image here</p>"


def test_checker_documents_vary_across_the_native_publication_surface():
    documents = [checker_module._publication_document() for _ in range(512)]

    categories = (
        lambda content: "<table" in content,
        lambda content: "<ul" in content or "<ol" in content,
        lambda content: "<script" in content,
        lambda content: "<style" in content,
        lambda content: "<!-- " in content,
        lambda content: any(
            tag in content for tag in ("<img", "<a", "<input", "<br", "<hr")
        ),
        lambda content: bool(re.search(r"<[a-z]{2,8}-[a-z]{2,8}\b", content)),
        lambda content: bool(re.search(r"<[a-z]{2,8}:[a-z]{2,8}\b", content)),
        lambda content: any(ord(character) > 0x7F for character in content),
        lambda content: bool(re.search(r"\s(?:data|aria)-[a-z]+=", content)),
    )

    assert len(set(documents)) == len(documents)
    assert any("<" not in content for content in documents)
    assert any(content.startswith("<!DOCTYPE html>") for content in documents)
    assert any(not content.startswith("<!DOCTYPE html>") for content in documents)
    opening_tag_counts = {
        len(re.findall(r"<(?![/!])", content)) for content in documents
    }
    assert len(opening_tag_counts) >= 8
    for category in categories:
        assert any(category(content) for content in documents)
        assert any(not category(content) for content in documents)
    assert any(not re.search(r"[A-Za-z0-9]{32}", content) for content in documents)
    for content in documents:
        assert all(ord(character) <= 0xFFFF for character in content)
        assert "<?" not in content
        assert "<head" not in content.lower()
        assert 'href="/' not in content and 'href="#' not in content
        assert 'src="/' not in content
        assert "!~!~!~" not in content

    mandatory_super_template = (
        "<table",
        "<ul",
        "<script>const ",
        "<style>.",
        "display:block;color:inherit",
        "<!-- ",
        'src="assets/',
        'href="pages/',
        "<input ",
        " itemscope draggable=",
    )
    assert all(
        not all(marker in content for marker in mandatory_super_template)
        for content in documents
    )


def test_checker_references_are_open_ended_without_native_normalization():
    references = [checker_module._reference() for _ in range(64)]

    assert len(set(references)) == len(references)
    for reference in references:
        assert 8 <= len(reference) <= 65
        assert reference[0].isalpha()
        assert reference[-1] != "-"
        assert "--" not in reference
        assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]+", reference)


def test_checker_requires_the_complete_document_not_only_random_text(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(checker_module, "login", lambda *_args: (object(), "token"))
    references = iter(("OrdinarySite", "OrdinaryPage"))
    monkeypatch.setattr(checker_module, "_reference", lambda: next(references))
    document = "<main data-layout='wide'><p>carried-text</p></main>"
    monkeypatch.setattr(checker_module, "_publication_document", lambda: document)
    monkeypatch.setattr(checker_module, "create_site_and_page", lambda *_args: 17)
    monkeypatch.setattr(checker_module, "update_page", lambda *_args: None)
    monkeypatch.setattr(
        checker_module,
        "render_public",
        lambda *_args: "<html><body>carried-text</body></html>",
    )

    result = DolibarrWebsiteChecker().run(cohort_target(monkeypatch))

    assert result.passed is False
    assert result.detail.endswith(": document was not preserved")


def test_old_fixed_template_allowlist_makes_decisive_health_red(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(checker_module, "login", lambda *_args: (object(), "token"))
    references = iter(("OrdinarySite", "OrdinaryPage"))
    monkeypatch.setattr(checker_module, "_reference", lambda: next(references))
    document = (
        "<main data-layout='wide'><p>ordinary flexible content</p>"
        "<table><tr><td>details</td></tr></table></main>"
    )
    monkeypatch.setattr(checker_module, "_publication_document", lambda: document)
    monkeypatch.setattr(checker_module, "create_site_and_page", lambda *_args: 17)
    old_envelope = re.compile(
        r"<article><h2>[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+</h2>"
        r"<p>This [a-z]+ [a-z]+ [a-z]+ [a-z]+ details for [a-z]+\.</p></article>"
    )
    assert old_envelope.fullmatch(
        "<article><h2>Coastal Design Guide</h2>"
        "<p>This guide presents coastal design details for visitors.</p></article>"
    )

    def allow_only_old_template(*args):
        if not old_envelope.fullmatch(args[-1]):
            raise checker_module.DolibarrError("publication rejected")

    monkeypatch.setattr(checker_module, "update_page", allow_only_old_template)

    result = DolibarrWebsiteChecker().run(cohort_target(monkeypatch))

    assert result.passed is False
    assert result.detail == "workflow failed: DolibarrError"


def test_mandatory_super_template_allowlist_makes_decisive_health_red(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(checker_module, "login", lambda *_args: (object(), "token"))
    references = iter(("OrdinarySite", "OrdinaryPage"))
    monkeypatch.setattr(checker_module, "_reference", lambda: next(references))
    document = "<p class='ordinary'>A simple Website page.</p>"
    monkeypatch.setattr(checker_module, "_publication_document", lambda: document)
    monkeypatch.setattr(checker_module, "create_site_and_page", lambda *_args: 17)
    mandatory_markers = (
        "<table",
        "<ul",
        "<script>const ",
        "<style>.",
        "display:block;color:inherit",
        "<!-- ",
        'src="assets/',
        'href="pages/',
        "<input ",
        " itemscope draggable=",
    )
    prior_super_template = "".join(mandatory_markers)
    assert all(marker in prior_super_template for marker in mandatory_markers)

    def allow_only_super_template(*args):
        if not all(marker in args[-1] for marker in mandatory_markers):
            raise checker_module.DolibarrError("publication rejected")

    monkeypatch.setattr(checker_module, "update_page", allow_only_super_template)

    result = DolibarrWebsiteChecker().run(cohort_target(monkeypatch))

    assert result.passed is False
    assert result.detail == "workflow failed: DolibarrError"


def test_long_alphanumeric_carrier_allowlist_makes_decisive_health_red(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    monkeypatch.setattr(checker_module, "login", lambda *_args: (object(), "token"))
    references = iter(("OrdinarySite", "OrdinaryPage"))
    monkeypatch.setattr(checker_module, "_reference", lambda: next(references))
    document = "<p>Ordinary words with punctuation.</p>"
    monkeypatch.setattr(checker_module, "_publication_document", lambda: document)
    monkeypatch.setattr(checker_module, "create_site_and_page", lambda *_args: 17)
    old_carrier = re.compile(r"[A-Za-z0-9]{32}")
    assert old_carrier.search("x" * 32)
    assert not old_carrier.search(document)

    def allow_only_old_carrier(*args):
        if not old_carrier.search(args[-1]):
            raise checker_module.DolibarrError("publication rejected")

    monkeypatch.setattr(checker_module, "update_page", allow_only_old_carrier)

    result = DolibarrWebsiteChecker().run(cohort_target(monkeypatch))

    assert result.passed is False
    assert result.detail == "workflow failed: DolibarrError"


def test_principal_provisioning_seals_equal_role_issued_editors(monkeypatch):
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    created = []
    monkeypatch.setattr(flag_handler_module, "_admin_password", lambda _target: "admin")
    monkeypatch.setattr(
        flag_handler_module,
        "login",
        lambda *_args: (object(), "token"),
    )
    monkeypatch.setattr(flag_handler_module, "configure_website", lambda *_args: None)
    monkeypatch.setattr(
        flag_handler_module,
        "ensure_editor",
        lambda _admin, _token, username, password, label: created.append(
            (username, password, label)
        ),
    )
    monkeypatch.setenv("CYBERARENA_FACILITY_TOKEN", "facility-secret")
    expected_sealed = seal_issued_cohort(
        [
            ["ed" + "a" * 14, "Aa1!" + "a" * 32],
            ["ed" + "b" * 14, "Aa1!" + "b" * 32],
        ]
    )
    sealed_commands = []

    def exec_in(_host, command):
        if COHORT_PATH in command:
            sealed_commands.append(command)
            return 0, expected_sealed
        return 0, ""

    runtime_target = target(exec_in)
    principals = DolibarrWebsiteChallenge().flag_handler.provision_principals(
        runtime_target,
        {"team-a": "a" * 64, "team-b": "b" * 64},
    )
    assert sealed_commands
    assert set(principals) == {"team-a", "team-b"}
    assert {username for username, _, _ in created} == {
        principal.principal_id for principal in principals.values()
    }


def test_certified_pov_uses_editor_workflow_and_proof_target(monkeypatch):
    published = {}
    monkeypatch.setattr(_exploit, "login", lambda *_args: (object(), "token"))
    monkeypatch.setattr(_exploit, "create_site_and_page", lambda *_args: 17)

    def update(_editor, _token, site, page_id, content):
        published.update(site=site, page_id=page_id, content=content)

    monkeypatch.setattr(_exploit, "update_page", update)
    monkeypatch.setattr(
        _exploit,
        "render_public",
        lambda *_args: "rendered FLAG{proof_from_service}",
    )
    recovered = _exploit.steal(
        "victim_prod",
        {"username": "editor", "password": "password"},
        "/proof/operation",
    )
    assert recovered == "FLAG{proof_from_service}"
    assert published["page_id"] == 17
    assert "<?PHP" in published["content"]
    assert 'shell_exec("/proof/operation")' in published["content"]


def test_certified_pov_reports_clean_block_as_success(monkeypatch, capsys):
    values = {
        "CYBERARENA_TEAM_TOKEN": "team-token",
        "CYBERARENA_SUBMIT_URL": "http://flag_service:8080/game/flag/submit",
    }
    monkeypatch.setattr(_exploit, "env", values.__getitem__)
    monkeypatch.setattr(
        _exploit,
        "post_json",
        lambda *_args, **_kwargs: {
            "targets": [
                {
                    "host": "victim_prod",
                    "service": "dolibarr-website",
                    "store": "service_command",
                    "flag_id": "/proof/operation",
                }
            ],
            "principals": [
                {
                    "host": "victim_prod",
                    "service": "dolibarr-website",
                    "credentials": {
                        "username": "editor",
                        "password": "password",
                    },
                }
            ],
        },
    )
    monkeypatch.setattr(_exploit, "steal", lambda *_args: None)

    assert _exploit.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "target_reached": True,
        "flag_recovered": False,
        "submission_status": "none",
    }


def test_certified_pov_reports_duplicate_submission_truthfully():
    assert _exploit.submission_status({"accepted": False, "reason": "DUPLICATE"}) == (
        "duplicate"
    )
