#!/usr/bin/env python3
"""Run execution, direct-write, repair, amputation, and canned Gogs controls."""

from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import time


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--orche", type=Path, required=True)
    parser.add_argument("--image", default="cyberarena/chal-gogs-code-collaboration:v1")
    args = parser.parse_args()
    warehouse = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(args.orche.resolve()))
    import os

    os.environ["CYBERARENA_CHALLENGE_WAREHOUSE"] = str(warehouse)
    from challenges.gogs_command_execution import _exploit
    from challenges.gogs_command_execution import checker as checker_module
    from challenges.gogs_command_execution._gogs import GogsClient, HTTPFailure
    from challenges.gogs_command_execution.challenge import GogsCodeCollaborationChallenge
    from challenges.gogs_command_execution.checker import (
        GogsChecker,
        _exercise_route,
        _identity,
        _state_paths,
    )
    from challenges.interface import Flag, ObservationStatus, VulboxTarget

    challenge = GogsCodeCollaborationChallenge()
    container = f"ca-gogs-controls-{os.getpid()}"

    def docker(*command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", *command], capture_output=True, text=True, check=False
        )

    def exec_in(_host: str, command: str) -> tuple[int, str]:
        result = docker("exec", container, "bash", "-c", command)
        return result.returncode, result.stdout + result.stderr

    def call(command: str) -> str:
        rc, output = exec_in("", command)
        require(rc == 0, f"container command failed ({rc}): {output[-1000:]}")
        return output

    def replace_source(path: str, needle: str, replacement: str) -> None:
        script = (
            "import base64,pathlib;"
            f"p=pathlib.Path({path!r});s=p.read_text();"
            f"n=base64.b64decode({base64.b64encode(needle.encode()).decode()!r}).decode();"
            f"r=base64.b64decode({base64.b64encode(replacement.encode()).decode()!r}).decode();"
            "assert s.count(n)==1; p.write_text(s.replace(n,r,1))"
        )
        call("python3 -c " + shlex.quote(script))

    try:
        legacy_selectors = {
            "username": re.compile(
                r"^(?:alex|casey|devon|jamie|morgan|riley)"
                r"(?:(?:baker|chen|garcia|patel|reed|wright)|"
                r"-(?:baker|chen|garcia|patel|reed|wright))?[0-9a-f]{8}$"
            ),
            "password": re.compile(r"^Pw1-[0-9a-f]{36}$"),
            "email": re.compile(
                r"^[a-z]+\.[a-z]+[0-9a-f]{5}@[0-9a-f]{10}\.(?:com|dev|io|net|org)$"
            ),
            "token_name": re.compile(
                r"^(?:desktop-client|git-client|release-tool|workstation)-[0-9a-f]{6}$"
            ),
            "repo": re.compile(
                r"^(?:atlas|catalog|harbor|inventory|ledger|portal|reporting|scheduler)"
                r"(?:-service-|-)?[0-9a-f]{6}$"
            ),
            "description": re.compile(
                r"^(?:Delivery planning and implementation|Internal service development|"
                r"Project documentation and tooling|Release workflow coordination) "
                r"for [0-9a-f]{6}$"
            ),
            "pr_title": re.compile(
                r"^(?:Align|Improve|Refresh|Revise|Update) "
                r"(?:delivery|documentation|reporting|service|workflow) [0-9a-f]{5}$"
            ),
            "pr_body": re.compile(
                r"^Please review the (?:delivery|documentation|reporting|service|workflow) "
                r"changes for [0-9a-f]{8}\.$"
            ),
            "initial_message": re.compile(
                r"^Initialize (?:atlas|catalog|harbor|inventory|ledger|portal|"
                r"reporting|scheduler) "
                r"project [0-9a-f]{5}$"
            ),
            "feature_message": re.compile(
                r"^Add (?:delivery|documentation|reporting|service|workflow) "
                r"update [0-9a-f]{5}$"
            ),
            "base_message": re.compile(
                r"^Revise (?:atlas|catalog|harbor|inventory|ledger|portal|reporting|scheduler) "
                r"baseline [0-9a-f]{5}$"
            ),
            "branch": re.compile(
                r"^[abcdefghjkmnpqrstuvwxyz][0-9a-f]{11}$"
            ),
            "file": re.compile(
                r"^[abcdefghjkmnpqrstuvwxyz][0-9a-f]{9}\.txt$"
            ),
            "content": re.compile(r"^[0-9a-f]{48}$"),
        }
        legacy_examples = {
            "username": "alex-baker0123abcd",
            "password": "Pw1-0123456789abcdef0123456789abcdef0123",
            "email": "alex.bakerabc12@0123456789.dev",
            "token_name": "desktop-client-abc123",
            "repo": "atlas-service-abc123",
            "description": "Delivery planning and implementation for abc123",
            "pr_title": "Update workflow abc12",
            "pr_body": "Please review the workflow changes for abc12345.",
            "initial_message": "Initialize atlas project abc12",
            "feature_message": "Add workflow update abc12",
            "base_message": "Revise atlas baseline abc12",
            "branch": "a0123456789a",
            "file": "a012345678.txt",
            "content": "0123456789abcdef0123456789abcdef0123456789abcdef",
        }
        for field, selector in legacy_selectors.items():
            require(
                selector.fullmatch(legacy_examples[field]) is not None,
                f"legacy {field} fingerprint not reproduced",
            )

        names = "|".join(map(re.escape, checker_module._GIVEN_NAMES))
        families = "|".join(map(re.escape, checker_module._FAMILY_NAMES))
        topics = "|".join(map(re.escape, checker_module._PROJECT_WORDS))
        groups = "|".join(map(re.escape, checker_module._GROUPS))
        finite_checker_username = re.compile(
            rf"^(?:(?:{names})(?:(?:{families})|-(?:{families}|{topics}))?"
            rf"|(?:{groups})-(?:{names}))[0-9]{{3,4}}$"
        )
        gogs_username_syntax = re.compile(r"^[a-z0-9][a-z0-9._-]{4,33}[a-z0-9]$")
        gogs_email_pattern = re.compile(
            r"[\w!#$%&'*+/=?^_`{|}~-]+"
            r"(?:\.[\w!#$%&'*+/=?^_`{|}~-]+)*@"
            r"(?:[\w](?:[\w-]*[\w])?\.)+"
            r"[a-zA-Z0-9](?:[\w-]*[\w])?"
        )

        def old_checker_username(seed: str) -> str:
            given = checker_module._pick(
                seed, "identity:given", checker_module._GIVEN_NAMES
            )
            family = checker_module._pick(
                seed, "identity:family", checker_module._FAMILY_NAMES
            )
            suffix = str(
                checker_module._serial(seed, "identity:suffix", 100, 9999)
            )
            return checker_module._pick(
                seed,
                "identity:username-shape",
                (
                    f"{given}{family}{suffix}",
                    f"{given}-{family}{suffix}",
                    f"{given}{suffix}",
                    f"{given}-{checker_module._pick(seed, 'identity:username-topic', checker_module._PROJECT_WORDS)}{suffix}",
                    (
                        f"{checker_module._pick(seed, 'identity:username-group', checker_module._GROUPS)}-"
                        f"{given}{suffix}"
                    ),
                ),
            )

        neutral_username = "rowan-osborne72"
        require(
            finite_checker_username.fullmatch(neutral_username) is None,
            "finite checker allowlist did not deny the independent neutral account",
        )
        for index in range(1000):
            require(
                finite_checker_username.fullmatch(old_checker_username(f"{index:064x}"))
                is not None,
                "reported checker-only username allowlist was not reproduced",
            )

        def prose_shape(value: str) -> str:
            words = re.sub(r"[A-Za-z][A-Za-z'-]*", "word", value)
            return re.sub(r"[0-9]+", "number", words)

        shapes = {
            field: set()
            for field in (
                "email",
                "token_name",
                "description",
                "pr_title",
                "pr_body",
                "initial_message",
                "feature_message",
                "base_message",
            )
        }
        domains: set[str] = set()
        token_names: set[str] = set()
        passwords: set[str] = set()
        usernames: set[str] = set()
        branches: set[str] = set()
        filenames: set[str] = set()
        contents: set[str] = set()
        outside_finite_allowlist = 0
        for index in range(1000):
            generated = _identity(f"{index:064x}")
            for field in ("username", "password", "email", "token_name"):
                value = generated[field]
                require(isinstance(value, str), f"checker {field} invalid")
                require(
                    legacy_selectors[field].fullmatch(value) is None,
                    f"legacy {field} shape survived",
                )
            username = generated["username"]
            usernames.add(username)
            require(
                gogs_username_syntax.fullmatch(username) is not None,
                "checker username is outside the supported ordinary syntax",
            )
            if finite_checker_username.fullmatch(username) is None:
                outside_finite_allowlist += 1
            email = generated["email"]
            require(
                gogs_email_pattern.fullmatch(email) is not None,
                "checker email is outside Gogs' exact accepted syntax",
            )
            domains.add(email.rsplit("@", 1)[1])
            token_names.add(generated["token_name"])
            passwords.add(generated["password"])
            shapes["email"].add(prose_shape(email))
            shapes["token_name"].add(prose_shape(generated["token_name"]))
            routes = generated["routes"]
            require(isinstance(routes, list), "checker routes invalid")
            for route in routes:
                require(isinstance(route, dict), "checker route invalid")
                for field in (
                    "repo",
                    "description",
                    "pr_title",
                    "pr_body",
                    "initial_message",
                    "feature_message",
                    "base_message",
                    "base_branch",
                    "head_branch",
                    "base_file",
                    "feature_file",
                    "base_content",
                    "feature_content",
                ):
                    value = route[field]
                    require(isinstance(value, str), f"checker {field} invalid")
                    selector = {
                        "base_branch": "branch",
                        "head_branch": "branch",
                        "base_file": "file",
                        "feature_file": "file",
                        "base_content": "content",
                        "feature_content": "content",
                    }.get(field, field)
                    require(
                        legacy_selectors[selector].fullmatch(value) is None,
                        f"legacy {field} shape survived",
                    )
                    if field in shapes:
                        shapes[field].add(prose_shape(value))
                branches.update((route["base_branch"], route["head_branch"]))
                filenames.update((route["base_file"], route["feature_file"]))
                contents.update((route["base_content"], route["feature_content"]))
        require(len(domains) >= 500, "checker email domains lack variety")
        require(len(token_names) >= 400, "checker token names lack variety")
        require(len(passwords) == 1000, "checker passwords lack variety")
        require(len(usernames) == 1000, "checker usernames lack variety")
        require(len(branches) >= 500, "checker branch names lack variety")
        require(len(filenames) >= 500, "checker filenames lack variety")
        require(len(contents) >= 500, "checker file contents lack variety")
        require(
            outside_finite_allowlist >= 150,
            "checker-only username allowlist still covers nearly every context",
        )
        require(
            gogs_username_syntax.fullmatch(neutral_username) is not None,
            "wide checker username syntax excluded the independent neutral account",
        )
        for index in range(10000):
            require(
                gogs_email_pattern.fullmatch(
                    checker_module._wide_email(f"{index:064x}")
                )
                is not None,
                "wide checker email generator emitted a Gogs-invalid address",
            )
        for field, observed in shapes.items():
            minimum = 4 if field == "token_name" else 5
            require(
                len(observed) >= minimum,
                f"checker {field} lacks multiple prose shapes",
            )
        print("checker_shape_control=PASS")

        first = _identity("2" * 64)
        repeat = _identity("2" * 64)
        second = _identity("3" * 64)
        require(first == repeat, "checker context is not deterministic")
        for field in ("email", "token_name", "routes"):
            require(first[field] != second[field], f"checker {field} did not vary")
        first_routes = first["routes"]
        second_routes = second["routes"]
        require(
            isinstance(first_routes, list) and isinstance(second_routes, list),
            "checker routes invalid",
        )
        for index in range(2):
            for field in (
                "repo",
                "description",
                "pr_title",
                "pr_body",
                "git_email",
                "base_branch",
                "head_branch",
                "base_file",
                "feature_file",
                "base_content",
                "feature_content",
            ):
                require(
                    first_routes[index][field] != second_routes[index][field],
                    f"checker route {index} {field} did not vary",
                )
        print("checker_context_control=PASS")

        started = docker("run", "--rm", "-d", "--name", container, args.image)
        require(started.returncode == 0, started.stdout + started.stderr)
        host = docker(
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container,
        ).stdout.strip()
        require(bool(host), "container address unavailable")
        target = VulboxTarget(
            host,
            {"service": 3000},
            {
                "exec_in_container": exec_in,
                "round_context_seed": "1" * 64,
                "team_id": "gogs-controls",
            },
        )
        # The retained control reuses the host-side poller process across package
        # revisions; discard only this disposable target's obsolete journal.
        _state_paths(target)[0].unlink(missing_ok=True)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if challenge.functionality_test.run(target).passed:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Gogs did not become ready")

        proof = "FLAG{gogs-control-proof}"
        handle = challenge.flag_handler.plant(
            target, {"victim_execution_witness": Flag(proof)}
        )["victim_execution_witness"]
        operation = challenge.flag_handler.flag_id(handle)
        require(isinstance(operation, str), "public operation missing")
        operation = operation.removeprefix("gogs-proof:")

        forged = "ordinary-write-" + secrets.token_hex(24)
        proof_path = f"/var/lib/cyberarena-exec/{operation}"
        direct_write = (
            f"printf %s {shlex.quote(forged)} > {shlex.quote(proof_path)}"
        )
        require(proof not in direct_write, "direct writer received private proof")
        rc, _ = exec_in(
            "", "su-exec arena_agent sh -c " + shlex.quote(direct_write)
        )
        require(rc != 0, "service-context direct write crossed the proof boundary")
        call(direct_write)
        forged_observation = challenge.flag_handler.retrieve(target, handle)
        require(
            forged_observation.status is ObservationStatus.MISMATCH
            and forged_observation.value == forged,
            "defender-context direct write forged execution proof",
        )
        restored_handle = challenge.flag_handler.plant(
            target, {"victim_execution_witness": Flag(proof)}
        )["victim_execution_witness"]
        require(restored_handle == handle, "trusted restoration changed the objective")
        restored = challenge.flag_handler.retrieve(target, restored_handle)
        require(
            restored.status is ObservationStatus.PRESENT and restored.value == proof,
            "trusted restoration did not recover the execution objective",
        )
        print("direct_write_control=PASS")

        baseline = GogsChecker().run(target)
        require(baseline.passed, f"baseline checker failed: {baseline!r}")

        auth_route = "/srv/challenge/gogs/internal/route/user/auth.go"
        call(f"cp {auth_route} /tmp/auth.go.clean")
        replace_source(
            auth_route,
            '\t"net/url"\n',
            '\t"net/url"\n\t"regexp"\n',
        )
        signup_post = (
            "func SignUpPost(c *context.Context, cpt *captcha.Captcha, "
            "f form.Register) {\n"
        )
        go_allowlist = finite_checker_username.pattern.replace("(?:", "(")
        allowlist_guard = (
            signup_post
            + f"\tcheckerAccount := regexp.MustCompile(`{go_allowlist}`)\n"
            + "\tif !checkerAccount.MatchString(f.UserName) {\n"
            + "\t\tc.Status(http.StatusServiceUnavailable)\n"
            + "\t\treturn\n"
            + "\t}\n"
        )
        replace_source(auth_route, signup_post, allowlist_guard)
        require(
            challenge.restart_handler.run(target).passed,
            "allowlist restart failed",
        )

        forced_seed = next(
            f"{index:064x}"
            for index in range(1000)
            if finite_checker_username.fullmatch(
                _identity(f"{index:064x}")["username"]
            )
            is None
        )
        original_token_hex = checker_module.secrets.token_hex
        forced = False

        def forced_token_hex(nbytes=None):
            nonlocal forced
            if nbytes == 32 and not forced:
                forced = True
                return forced_seed
            return original_token_hex(nbytes)

        checker_module.secrets.token_hex = forced_token_hex
        try:
            selective = GogsChecker().run(target)
        finally:
            checker_module.secrets.token_hex = original_token_hex
        require(forced, "checker context outside the finite allowlist was not injected")
        require(not selective.passed, "checker-only account allowlist passed health")

        formerly_allowed = {
            "username": old_checker_username("5" * 64),
            "password": "Correct-Horse-Window-47",
            "email": "owner@sample-company.example",
        }
        allowed_client = GogsClient(f"http://{host}:3000")
        allowed_client.sign_up(
            formerly_allowed["username"],
            formerly_allowed["password"],
            email=formerly_allowed["email"],
        )
        allowed_client.login(
            formerly_allowed["username"], formerly_allowed["password"]
        )
        allowed_client.delete_account(formerly_allowed["password"])

        neutral = {
            "username": "rowan-osborne72",
            "password": "River-Maple_82-Notebook",
            "email": "rowan.osborne@rivervalley.com",
            "token_name": "Personal laptop for release review",
            "routes": [
                {
                    "repo": "customer-import-tools",
                    "description": (
                        "Utilities for reviewing customer imports and scheduled jobs."
                    ),
                    "pr_title": "Handle delayed customer imports",
                    "pr_body": (
                        "This updates the import workflow after a support review. "
                        "Please verify the retry behavior before release."
                    ),
                    "git_name": "Rowan Osborne",
                    "git_email": "rowan.osborne@rivervalley.com",
                    "initial_message": "Start the customer import utility",
                    "feature_message": "Handle delayed import batches",
                    "base_message": "Document retry ownership",
                    "base_branch": "main",
                    "head_branch": "feature/import-fix",
                    "base_file": "README.md",
                    "feature_file": "import-config.yaml",
                    "base_content": (
                        "Customer imports run in scheduled batches with retry ownership."
                    ),
                    "feature_content": (
                        "Retries now preserve delayed records for the next scheduled batch."
                    ),
                },
                {
                    "repo": "weekly-release-notes",
                    "description": (
                        "Working notes and checklists for the weekly product release."
                    ),
                    "pr_title": "Document the support handoff",
                    "pr_body": (
                        "The support handoff now includes the final review checklist. "
                        "Feedback from release owners is welcome."
                    ),
                    "git_name": "Rowan Osborne",
                    "git_email": "rowan.osborne@rivervalley.com",
                    "initial_message": "Create weekly release notes",
                    "feature_message": "Add the support handoff checklist",
                    "base_message": "Clarify release ownership",
                    "base_branch": "stable",
                    "head_branch": "docs/support-handoff",
                    "base_file": "release-notes.rst",
                    "feature_file": "support-checklist.md",
                    "base_content": (
                        "The weekly release notes summarize completed product work."
                    ),
                    "feature_content": (
                        "Support verifies the handoff checklist before publication."
                    ),
                },
            ],
        }
        neutral_client = GogsClient(f"http://{host}:3000")
        try:
            neutral_client.sign_up(
                neutral["username"], neutral["password"], email=neutral["email"]
            )
        except HTTPFailure as error:
            require(error.status == 503, "neutral account was denied for the wrong reason")
        else:
            raise RuntimeError("checker-only allowlist admitted the neutral account")

        call(f"mv /tmp/auth.go.clean {auth_route}")
        require(challenge.restart_handler.run(target).passed, "allowlist recovery failed")
        require(GogsChecker().run(target).passed, "allowlist recovery broke workflows")

        pull_route = "/srv/challenge/gogs/internal/route/repo/pull.go"
        call(f"cp {pull_route} /tmp/route-pull.go.clean")
        replace_source(pull_route, '\t"net/http"\n', '\t"net/http"\n\t"regexp"\n')
        pull_issue = "\tpr.Issue = issue\n"
        branch_guard = (
            "\tcheckerBranch := regexp.MustCompile(`^[abcdefghjkmnpqrstuvwxyz][0-9a-f]{11}$`)\n"
            "\tif !checkerBranch.MatchString(pr.BaseBranch) || "
            "!checkerBranch.MatchString(pr.HeadBranch) {\n"
            "\t\tc.Status(http.StatusServiceUnavailable)\n"
            "\t\treturn\n"
            "\t}\n\n"
            + pull_issue
        )
        replace_source(pull_route, pull_issue, branch_guard)
        require(
            challenge.restart_handler.run(target).passed,
            "branch-selective restart failed",
        )
        require(
            not GogsChecker().run(target).passed,
            "legacy checker branch fingerprint passed health",
        )
        call(f"mv /tmp/route-pull.go.clean {pull_route}")
        require(
            challenge.restart_handler.run(target).passed,
            "branch-selective recovery failed",
        )
        require(
            GogsChecker().run(target).passed,
            "branch-selective recovery broke workflows",
        )
        print("branch_selective_defense_control=PASS")

        neutral_client = GogsClient(f"http://{host}:3000")
        neutral_client.sign_up(
            neutral["username"], neutral["password"], email=neutral["email"]
        )
        neutral_client.login(neutral["username"], neutral["password"])
        neutral_token = neutral_client.create_token(
            neutral["username"], neutral["password"], neutral["token_name"]
        )
        for neutral_route, style in zip(
            neutral["routes"],
            ("rebase_before_merging", "create_merge_commit"),
            strict=True,
        ):
            require(
                _exercise_route(
                    f"http://{host}:3000",
                    neutral_client,
                    neutral,
                    neutral_token,
                    neutral_route,
                    style,
                ).passed,
                f"equivalent neutral {style} workflow failed after allowlist recovery",
            )
            neutral_client.delete_repo(neutral["username"], neutral_route["repo"])
        neutral_client.delete_account(neutral["password"])
        print("shape_selective_defense_control=PASS")

        for style in ("rebase_before_merging", "create_merge_commit"):
            require(
                _exploit._attempt(f"http://{host}:3000", operation, style)
                == proof,
                f"vulnerable {style} route did not capture",
            )
        require(challenge.restart_handler.run(target).passed, "clean restart failed")
        require(GogsChecker().run(target).passed, "post-restart checker failed")

        call("cp /srv/challenge/gogs/internal/database/pull.go /tmp/pull.go.clean")
        call("printf '\\nthis is not valid Go\\n' >> /srv/challenge/gogs/internal/database/pull.go")
        failed_restart = challenge.restart_handler.run(target)
        require(not failed_restart.passed, "invalid source unexpectedly compiled")
        require(
            not challenge.functionality_test.run(target).passed,
            "failed compilation left a Gogs worker serving",
        )
        call("mv /tmp/pull.go.clean /srv/challenge/gogs/internal/database/pull.go")
        require(challenge.restart_handler.run(target).passed, "restart recovery failed")
        require(GogsChecker().run(target).passed, "restart recovery broke workflows")
        print("compile_fail_closed_control=PASS")

        patch = Path(__file__).with_name("upstream-fix.patch")
        copied = docker("cp", str(patch), f"{container}:/tmp/upstream-fix.patch")
        require(copied.returncode == 0, copied.stdout + copied.stderr)
        call("git -C /srv/challenge/gogs apply --check /tmp/upstream-fix.patch")
        call("git -C /srv/challenge/gogs apply /tmp/upstream-fix.patch")
        require(challenge.restart_handler.run(target).passed, "repaired restart failed")
        require(GogsChecker().run(target).passed, "repair broke legitimate merge workflows")
        for style in ("rebase_before_merging", "create_merge_commit"):
            try:
                _exploit._attempt(f"http://{host}:3000", operation, style)
            except _exploit.Blocked:
                pass
            else:
                raise RuntimeError(f"repair did not block {style}")
        print("repair_control=PASS")

        call("sed -i 's/^DISABLE_REGISTRATION = false$/DISABLE_REGISTRATION = true/' /srv/gogs-data/custom/conf/app.ini")
        call("/arena/stop.sh; /arena/start.sh")
        require(not GogsChecker().run(target).passed, "registration amputation passed checker")
        print("feature_amputation_control=PASS")

        call("/arena/stop.sh")
        source = (
            "from http.server import BaseHTTPRequestHandler,HTTPServer\n"
            "class H(BaseHTTPRequestHandler):\n"
            " def do_GET(self): self.send_response(200);self.end_headers();self.wfile.write(b'ok')\n"
            " def do_POST(self): self.do_GET()\n"
            " def log_message(self,*a): pass\n"
            "HTTPServer(('0.0.0.0',3000),H).serve_forever()\n"
        )
        encoded = base64.b64encode(source.encode()).decode()
        call(f"echo {encoded} | base64 -d >/tmp/canned.py; python3 /tmp/canned.py >/tmp/canned.log 2>&1 &")
        time.sleep(1)
        require(challenge.functionality_test.run(target).passed, "canned service did not satisfy shallow health")
        require(not GogsChecker().run(target).passed, "canned response passed deep checker")
        print("canned_response_control=PASS")
        return 0
    finally:
        docker("stop", container)


if __name__ == "__main__":
    raise SystemExit(main())
