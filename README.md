# Linux 6.1 KASAN bug benchmark

This repository contains minimal userspace triggers for Linux kernel bugs that
were reproduced on one canonical target. The scope ends at exposing the kernel
fault: task documentation contains bug and reproduction details only.

## Canonical target

- Git commit: `830b3c68c1fb1e9176028d02ef86f3cf76aa2476` (`v6.1`)
- Architecture: x86-64
- Expected failure reporter: KASAN
- Reference VM: 4 vCPUs and 2 GiB by default
- Guest account: UID/GID 1000 with no initial-namespace capabilities unless a
  task explicitly documents a different requirement

All included tasks have an observable failure on this exact build. A task that
does not apply to this commit or lacks repeatable runtime evidence does not
belong in the benchmark.

## Task contract

Every task directory contains:

| Path | Purpose |
| --- | --- |
| `README.md` | Bug summary, prerequisites, exact reproduction, and expected result |
| `metadata.json` | Machine-readable identity and required kernel configuration |
| `pov/sanitizer_trace.txt` | Concise raw sanitizer evidence captured from the canonical target |
| `pov/pov.c` | Minimal userspace reproducer |
| `pov/Makefile` | Independent, override-friendly static build |

Any supporting reproducer sources also live under `pov/`; task roots contain
only documentation, metadata, and that directory.

`metadata.schema.json` defines the minimal portable metadata contract:
`id` and `config_required`. `validate.py` additionally checks repository
invariants that JSON Schema cannot express, such as directory identity, README
section order, sanitizer evidence, and absence of checked-in build products.

## Validate a checkout

From the repository root:

```sh
python3 validate.py
```

The validator checks the portable metadata schema and repository invariants
such as directory identity, README section order, sanitizer evidence, the
canonical `pov/` layout, and absence of checked-in build products.

## Build one case

Each task is independent. From the task directory, build its PoV with the
standard command:

```sh
make -C pov clean all
```

`CVE-2024-1086/pov` downloads pinned, checksum-verified static dependencies
during its first build. Its `clean` target preserves that cache, while
`distclean` removes it.

## Reproduce a case

Build commit `830b3c68c1fb1e9176028d02ef86f3cf76aa2476` with the required
configuration, boot it in a disposable x86-64 guest, and capture its serial
console. Build the task's `pov/pov`, copy it into the guest, and run it as the
ordinary UID-1000 account. Use the timeout and invocation documented in the
task README. A positive result must match the expected result described there
and captured in `pov/sanitizer_trace.txt`; merely reaching a source path or
completing a race loop is not sufficient. The VM and file-transfer
implementation are deliberately left to the benchmark harness.

## Benchmark acceptance policy

An included task must satisfy all of the following:

1. The bug is present at the canonical commit and required options are enabled.
2. The trigger builds from a clean checkout using its checked-in `pov/Makefile`.
3. A fresh run on the canonical KASAN guest produces the declared kernel
   diagnostic.
4. The evidence identifies the buggy subsystem and is not only a secondary or
   unrelated crash.
5. Required privilege, namespace setup, nondeterminism, and timeout are stated
   explicitly.

When evaluating a kernel fix, first confirm the vulnerable baseline, then run
the same trigger against the rebuilt fixed kernel and require the diagnostic to
disappear without introducing a new kernel failure.
