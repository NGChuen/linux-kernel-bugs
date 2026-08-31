#!/usr/bin/env python3
"""Validate the kernel bug benchmark's checked-in task contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
README_HEADINGS = [
    "Summary",
    "Prerequisites",
    "Reproduce",
    "Expected result",
]
REPRODUCE_INTRO = "Build and copy `pov/pov` into the guest, then run:"
TOP_KEYS = {"id", "config_required"}
CONFIG_PATTERN = re.compile(r"^CONFIG_[A-Z0-9_]+=.+$")
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

        task_id = metadata["id"]
        if not is_nonempty_string(task_id):
            errors.append(f"{task_name}: id must be a non-empty string")
        else:
            if task_id != task_name:
                errors.append(f"{task_name}: id must match directory name")
            if task_id in seen_ids:
                errors.append(f"{task_name}: duplicate task id")
            seen_ids.add(task_id)

        expected_root_entries = {
            "README.md",
            "metadata.json",
            "pov",
        }
        unexpected_root_entries = sorted(
            path.name
            for path in task_dir.iterdir()
            if path.name not in expected_root_entries
        )
        if unexpected_root_entries:
            errors.append(
                f"{task_name}: unexpected task-root entries: "
                + ", ".join(unexpected_root_entries)
            )

        config = metadata["config_required"]
        if not isinstance(config, list) or not config or not all(
            is_nonempty_string(item) and CONFIG_PATTERN.fullmatch(item)
            for item in config
        ):
            errors.append(
                f"{task_name}: config_required must be a non-empty CONFIG_* array"
            )
        elif len(config) != len(set(config)):
            errors.append(f"{task_name}: config_required contains duplicates")

        required_files = [
            "README.md",
            "pov/sanitizer_trace.txt",
            "pov/Makefile",
            "pov/pov.c",
        ]
        for filename in required_files:
            path = task_dir / filename
            if not path.is_file() or path.stat().st_size == 0:
                errors.append(f"{task_name}: missing or empty {filename}")

        evidence_path = task_dir / "pov/sanitizer_trace.txt"
        if evidence_path.is_file():
            evidence = evidence_path.read_text(encoding="utf-8", errors="replace")
            if "KASAN" not in evidence and "WARNING:" not in evidence:
                errors.append(
                    f"{task_name}: evidence has no KASAN diagnostic or kernel warning"
                )

        readme_path = task_dir / "README.md"
        if readme_path.is_file():
            readme = readme_path.read_text(encoding="utf-8", errors="replace")
            headings = re.findall(r"^## (.+)$", readme, flags=re.MULTILINE)
            if headings != README_HEADINGS:
                errors.append(f"{task_name}: README section order is not canonical")
            if f"## Reproduce\n\n{REPRODUCE_INTRO}\n" not in readme:
                errors.append(f"{task_name}: README reproduction intro is not canonical")

        makefile_path = task_dir / "pov" / "Makefile"
        if makefile_path.is_file():
            makefile = makefile_path.read_text(encoding="utf-8", errors="replace")
            for fragment in (
                "TARGET := pov",
                "$(TARGET): pov.c",
                "CC ?=",
                "CPPFLAGS ?=",
                "CFLAGS ?=",
                "LDFLAGS ?=",
            ):
                if fragment not in makefile:
                    errors.append(f"{task_name}: pov/Makefile missing {fragment!r}")

        if (task_dir / "pov" / "pov").exists():
            errors.append(f"{task_name}: checked-in build product pov/pov is present")
        for forbidden in ("exploit.md", "gdb-verify.cmd", "runtime-gdb.txt"):
            for parent in (task_dir, task_dir / "pov"):
                if (parent / forbidden).exists():
                    relative = (parent / forbidden).relative_to(task_dir)
                    errors.append(
                        f"{task_name}: forbidden artifact {relative} is present"
                    )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print(f"validation failed: {len(errors)} error(s)", file=sys.stderr)
        return 1

    print(f"validated {len(metadata_files)} verified kernel bug tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
