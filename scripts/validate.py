#!/usr/bin/env python3
"""Validate the kernel bug benchmark's checked-in task contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
TARGET_COMMIT = "830b3c68c1fb1e9176028d02ef86f3cf76aa2476"
README_HEADINGS = [
    "Summary",
    "Target",
    "Prerequisites",
    "Build",
    "Reproduce",
    "Expected result",
    "Verified result",
]
TOP_KEYS = {
    "schema_version",
    "id",
    "title",
    "subsystem",
    "bug_class",
    "cve",
    "target",
    "trigger",
    "expected",
    "reproduction",
}
NESTED_KEYS = {
    "target": {"kernel", "git_commit", "config_required"},
    "trigger": {
        "source",
        "binary",
        "run_as",
        "timeout_seconds",
        "deterministic",
    },
    "expected": {"sanitizer", "signature"},
    "reproduction": {"status", "evidence"},
}
PORTABILITY_PATTERNS = [
    re.compile("/" + "home" + "/"),
    re.compile("/" + "data" + "/"),
    re.compile("local" + "host", re.IGNORECASE),
]


def is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def main() -> int:
    errors: list[str] = []

    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in {".md", ".json", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in PORTABILITY_PATTERNS:
            if pattern.search(text):
                errors.append(
                    f"{path.relative_to(ROOT)}: contains environment-specific text"
                )
                break

    metadata_files = sorted(ROOT.glob("*/metadata.json"))
    if not metadata_files:
        errors.append("no task metadata files found")

    seen_ids: set[str] = set()
    for metadata_path in metadata_files:
        task_dir = metadata_path.parent
        task_name = task_dir.name

        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append(f"{task_name}: cannot parse metadata.json: {exc}")
            continue

        if not isinstance(metadata, dict):
            errors.append(f"{task_name}: metadata root must be an object")
            continue
        if set(metadata) != TOP_KEYS:
            errors.append(f"{task_name}: metadata top-level keys do not match schema")
            continue
        for key, expected_keys in NESTED_KEYS.items():
            value = metadata[key]
            if not isinstance(value, dict) or set(value) != expected_keys:
                errors.append(f"{task_name}: {key} keys do not match schema")

        task_id = metadata["id"]
        if task_id != task_name:
            errors.append(f"{task_name}: id must match directory name")
        if task_id in seen_ids:
            errors.append(f"{task_name}: duplicate task id")
        seen_ids.add(task_id)

        for key in ("id", "title", "subsystem", "bug_class"):
            if not is_nonempty_string(metadata[key]):
                errors.append(f"{task_name}: {key} must be a non-empty string")

        cve = metadata["cve"]
        if task_name.startswith("CVE-"):
            if cve != task_name:
                errors.append(f"{task_name}: cve must match task id")
        elif cve is not None:
            errors.append(f"{task_name}: non-CVE task must use null cve")

        target = metadata["target"]
        if target.get("kernel") != "6.1-kasan":
            errors.append(f"{task_name}: target.kernel must be 6.1-kasan")
        if target.get("git_commit") != TARGET_COMMIT:
            errors.append(f"{task_name}: target.git_commit is not canonical")
        config = target.get("config_required")
        if not isinstance(config, list) or not config or not all(
            is_nonempty_string(item) for item in config
        ):
            errors.append(f"{task_name}: config_required must be a non-empty string array")
        elif len(config) != len(set(config)):
            errors.append(f"{task_name}: config_required contains duplicates")
        elif "CONFIG_KASAN=y" not in config:
            errors.append(f"{task_name}: config_required must include CONFIG_KASAN=y")

        trigger = metadata["trigger"]
        if trigger.get("source") != "trigger.c" or trigger.get("binary") != "trigger":
            errors.append(f"{task_name}: trigger source/binary names are not canonical")
        if not is_nonempty_string(trigger.get("run_as")):
            errors.append(f"{task_name}: trigger.run_as must be non-empty")
        timeout = trigger.get("timeout_seconds")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
            errors.append(f"{task_name}: timeout_seconds must be a positive integer")
        if not isinstance(trigger.get("deterministic"), bool):
            errors.append(f"{task_name}: deterministic must be boolean")

        expected = metadata["expected"]
        reporter = expected.get("sanitizer")
        signature = expected.get("signature")
        if reporter not in {"KASAN", "kernel-warning"}:
            errors.append(f"{task_name}: unsupported expected reporter {reporter!r}")
        if not is_nonempty_string(signature):
            errors.append(f"{task_name}: expected.signature must be non-empty")

        reproduction = metadata["reproduction"]
        if reproduction.get("status") != "verified":
            errors.append(f"{task_name}: included tasks must be verified")
        if reproduction.get("evidence") != "runtime-console.txt":
            errors.append(f"{task_name}: evidence path must be runtime-console.txt")

        required_files = ["README.md", "Makefile", "trigger.c", "runtime-console.txt"]
        for filename in required_files:
            path = task_dir / filename
            if not path.is_file() or path.stat().st_size == 0:
                errors.append(f"{task_name}: missing or empty {filename}")

        evidence_path = task_dir / "runtime-console.txt"
        if evidence_path.is_file():
            evidence = evidence_path.read_text(encoding="utf-8", errors="replace")
            if reporter == "KASAN" and "KASAN" not in evidence:
                errors.append(f"{task_name}: evidence has no KASAN diagnostic")
            if reporter == "kernel-warning" and "WARNING:" not in evidence:
                errors.append(f"{task_name}: evidence has no kernel warning")
            match = re.search(r"\bin ([A-Za-z_][A-Za-z0-9_.]*)", signature or "")
            if match and match.group(1) not in evidence:
                errors.append(
                    f"{task_name}: evidence does not contain signature token {match.group(1)}"
                )

        readme_path = task_dir / "README.md"
        if readme_path.is_file():
            readme = readme_path.read_text(encoding="utf-8", errors="replace")
            headings = re.findall(r"^## (.+)$", readme, flags=re.MULTILINE)
            if headings != README_HEADINGS:
                errors.append(f"{task_name}: README section order is not canonical")

        makefile_path = task_dir / "Makefile"
        if makefile_path.is_file():
            makefile = makefile_path.read_text(encoding="utf-8", errors="replace")
            for fragment in ("TARGET := trigger", "CC ?=", "CPPFLAGS ?=", "CFLAGS ?=", "LDFLAGS ?="):
                if fragment not in makefile:
                    errors.append(f"{task_name}: Makefile missing {fragment!r}")

        if (task_dir / "trigger").exists():
            errors.append(f"{task_name}: checked-in build product trigger is present")
        for forbidden in ("exploit.md", "gdb-verify.cmd", "runtime-gdb.txt"):
            if (task_dir / forbidden).exists():
                errors.append(f"{task_name}: forbidden artifact {forbidden} is present")

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"validation failed: {len(errors)} error(s)", file=sys.stderr)
        return 1

    print(f"validated {len(metadata_files)} verified kernel bug tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
