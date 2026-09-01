from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_exact_runtime_source_and_toolchain_pins() -> None:
    dockerfile = (ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    assert "a604f143dbb145a16cd58d22b1451826ee59fcf9de561dc6d698b1de222272d0" in dockerfile
    assert "6b96ceff49a8b6a5cb85773061d2ee8b1bef8f56" in dockerfile
    assert "golang:1.25.8-alpine@sha256:8e02eb337d9e0ea459e041f1ee5eece41cbb61f1d83e7d883a3e2fb4862063fa" in dockerfile
    assert "go mod download all" in dockerfile
    assert "tar -C /srv/challenge -czf /out/grafana-source.tar.gz grafana" in dockerfile
    assert "tar -C /go/pkg/mod -czf /out/grafana-go-mod.tar.gz ." in dockerfile
    assert "COPY --from=source /out/grafana-source.tar.gz /opt/arena/assets/grafana-source.tar.gz" in dockerfile
    assert "COPY --from=source /out/grafana-go-mod.tar.gz /opt/arena/assets/grafana-go-mod.tar.gz" in dockerfile


def test_build_and_restart_use_the_proven_combined_backend() -> None:
    dockerfile = (ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    restart = (ROOT / "image" / "restart.sh").read_text(encoding="utf-8")
    control = (ROOT / "image" / "service-control.sh").read_text(encoding="utf-8")
    for text in (dockerfile, restart):
        assert "-build-tags=oss build-backend" in text
        assert "build-server" not in text
    assert "/usr/share/grafana/bin/grafana server" in control
    assert "GOPROXY=off" in restart
    assert 'GOMODCACHE="$module_cache"' in restart
    assert restart.index("go run build.go") < restart.index("service-control.sh stop")


def test_helper_and_ssh_contracts_are_explicit() -> None:
    dockerfile = (ROOT / "image" / "Dockerfile").read_text(encoding="utf-8")
    helper = (ROOT / "image" / "grafana-objective.c").read_text(encoding="utf-8")
    entrypoint = (ROOT / "image" / "entrypoint.sh").read_text(encoding="utf-8")
    assert "chmod 4750 /usr/local/bin/grafana-objective" in dockerfile
    assert "getuid() != SERVICE_UID" in helper
    assert "PermitRootLogin prohibit-password" in dockerfile
    assert "trap '' HUP" in entrypoint
    assert "rm -f /run/grafana/arena.ready" in entrypoint


def test_runtime_hydrates_archived_source_and_module_cache() -> None:
    entrypoint = (ROOT / "image" / "entrypoint.sh").read_text(encoding="utf-8")
    restart = (ROOT / "image" / "restart.sh").read_text(encoding="utf-8")
    assert 'tar -xzf "$source_archive" -C /srv/challenge' in entrypoint
    assert 'tar -xzf "$source_archive" -C /srv/challenge' in restart
    assert 'tar -xzf "$module_archive" -C "$module_cache"' in restart


def test_principal_role_validation_uses_membership_api() -> None:
    facility = (ROOT / "image" / "facility.py").read_text(encoding="utf-8")
    assert '"/api/user/orgs"' in facility
    assert 'profile.get("orgRole")' not in facility


def test_prompt_does_not_disclose_advisory_or_proof_state() -> None:
    prompt = (ROOT / "prompts.py").read_text(encoding="utf-8")
    assert "CVE-2026-21724" not in prompt
    assert "/opt/arena/objective" not in prompt
    assert "/arena/secrets" not in prompt
