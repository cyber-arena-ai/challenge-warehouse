from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FINALIZE = ROOT / "image" / "finalize-generation.sh"


def promote_current(runtime: Path, candidate: Path) -> None:
    temporary = runtime / ".current.test"
    temporary.symlink_to(candidate)
    os.replace(temporary, runtime / "current")


def test_repeated_success_keeps_only_the_serving_generation(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    generations = runtime / "generations"
    original = generations / "original"
    first = generations / "first"
    second = generations / "second"
    for generation in (original, first, second):
        generation.mkdir(parents=True)
        (generation / "index.php").write_text(generation.name)
    (runtime / "current").symlink_to(original)
    (runtime / "last-good").symlink_to(original)

    promote_current(runtime, first)
    subprocess.run([FINALIZE, runtime, first, original], check=True)
    assert (runtime / "current").resolve() == first
    assert (runtime / "last-good").resolve() == first
    assert first.is_dir()
    assert not original.exists()

    promote_current(runtime, second)
    subprocess.run([FINALIZE, runtime, second, first], check=True)
    assert (runtime / "current").resolve() == second
    assert (runtime / "last-good").resolve() == second
    assert second.is_dir()
    assert not first.exists()
    assert [path.name for path in generations.iterdir()] == ["second"]
