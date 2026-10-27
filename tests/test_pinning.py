"""Every dependency is pinned, so a build next month runs the code that was tested today."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _lines(name):
    out = []
    for raw in (ROOT / name).read_text().splitlines():
        line = raw.split("#")[0].strip()
        if line:
            out.append(line)
    return out


def _canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def test_every_requirement_is_pinned_exactly():
    for name in ("requirements.txt", "requirements-dev.txt"):
        for line in _lines(name):
            if line.startswith("-"):
                continue
            assert "==" in line and not re.search(r"[<>~]=?", line.replace("==", "")), (name, line)


def test_the_constraints_file_is_used_and_pins_everything_exactly():
    assert "-c constraints.txt" in _lines("requirements.txt")
    pinned = {}
    for line in _lines("constraints.txt"):
        m = re.fullmatch(r"([A-Za-z0-9_.\-]+)==([^\s;]+)", line)
        assert m, line
        pinned[_canon(m.group(1))] = m.group(2)
    assert len(pinned) > 40


def test_requirements_agree_with_the_constraints():
    pinned = {}
    for line in _lines("constraints.txt"):
        name, version = line.split("==")
        pinned[_canon(name)] = version
    for name in ("requirements.txt", "requirements-dev.txt"):
        for line in _lines(name):
            if line.startswith("-"):
                continue
            pkg, version = line.split("==")
            pkg = re.sub(r"\[.*\]", "", pkg)
            assert pinned.get(_canon(pkg)) == version, (pkg, version, pinned.get(_canon(pkg)))


def test_the_image_is_built_in_two_stages_and_runs_without_build_tools():
    docker = (ROOT / "Dockerfile").read_text()
    stages = re.findall(r"^FROM .*$", docker, re.M)
    assert len(stages) == 2 and "AS builder" in stages[0]
    cut = docker.rindex("\nFROM ")
    first, runtime = docker[:cut], docker[cut:]
    assert "build-essential" not in runtime
    assert "COPY --from=builder /opt/venv /opt/venv" in runtime
    assert "USER jnvoy" in runtime and "--workers" in runtime
    assert "constraints.txt" in first


def test_the_image_is_built_and_started_in_ci_before_any_deploy():
    ci = (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    assert "docker build" in ci and "docker run" in ci
