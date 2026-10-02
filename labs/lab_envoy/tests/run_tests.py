#!/usr/bin/env python3
"""Altprobe lab test runner (pytest).

Usage:
    python3 run_tests.py                 # all categories
    python3 run_tests.py smoke           # smoke | function | security | e2e | geo | sbom
    python3 run_tests.py smoke -k mcp    # extra args are passed to pytest

Artifacts (in tests/logs/):
    junit-<category>.xml   pytest JUnit XML report
    altprobe.log           full Altprobe container log (debug includes the
                           collector's stdout; set LAB_ALTPROBE_CONTAINER to
                           override auto-detection)

Environment: LAB_BASE, LAB_OS_BASE, LAB_INDEX_WAIT, LAB_REDIS_HOST,
LAB_REDIS_PORT, LAB_REDIS_KEY.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "logs")

CATEGORIES = {
    "smoke": ["altprobe_lab/test_smoke.py"],
    "function": ["altprobe_lab/test_function.py"],
    "security": ["altprobe_lab/test_security.py"],
    "e2e": ["altprobe_lab/test_e2e.py"],
    "geo": ["altprobe_lab/test_geo.py"],
    "sbom": ["altprobe_lab/test_sbom.py"],
}


def docker_cli():
    for name in ("docker", "docker.exe"):
        try:
            subprocess.check_output([name, "--version"],
                                    stderr=subprocess.DEVNULL, text=True)
            return name
        except Exception:
            continue
    return None


def find_altprobe_container(cli):
    if not cli:
        return None
    try:
        out = subprocess.check_output(
            [cli, "ps", "--filter", "name=altprobe", "--format", "{{.Names}}"],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    for line in out.splitlines():
        name = line.strip()
        if name and "opensearch" not in name and "init" not in name:
            return name
    return None


def capture_altprobe_log():
    os.makedirs(LOGS, exist_ok=True)
    path = os.path.join(LOGS, "altprobe.log")
    cli = docker_cli()
    container = os.environ.get("LAB_ALTPROBE_CONTAINER") or find_altprobe_container(cli)
    with open(path, "w", encoding="utf-8", errors="replace") as handle:
        if not container or not cli:
            handle.write("Altprobe container not found. Set LAB_ALTPROBE_CONTAINER "
                         "or make the docker CLI available.\n")
            return
        handle.write("container: %s\n\n" % container)
        try:
            subprocess.run([cli, "logs", container], stdout=handle,
                           stderr=subprocess.STDOUT, text=True)
        except Exception as exc:  # pragma: no cover - best effort
            handle.write("failed to capture logs: %s\n" % exc)


def main():
    argv = sys.argv[1:]
    if argv and not argv[0].startswith("-"):
        category, extra = argv[0], argv[1:]
    else:
        category, extra = "all", argv

    if category == "all":
        targets = [target for group in CATEGORIES.values() for target in group]
    elif category in CATEGORIES:
        targets = CATEGORIES[category]
    else:
        print("unknown category %r; choose: all, %s" % (category, ", ".join(CATEGORIES)))
        return 2

    os.makedirs(LOGS, exist_ok=True)
    junit = os.path.join(LOGS, "junit-%s.xml" % category)

    try:
        import pytest  # noqa: F401
    except ImportError:
        print("pytest is required: python3 -m pip install -r requirements.txt")
        return 2

    cmd = [sys.executable, "-m", "pytest", "-v", "--junitxml=" + junit] + extra + targets
    status = subprocess.call(cmd, cwd=HERE)

    capture_altprobe_log()

    print("\nJUnit XML   : %s" % junit)
    print("Altprobe log: %s" % os.path.join(LOGS, "altprobe.log"))
    return status


if __name__ == "__main__":
    sys.exit(main())
