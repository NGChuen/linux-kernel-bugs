# syzbot 4b44a54ec1549ca9274715d46562bd9da3a43e65

## Summary

A race in AF_UNIX urgent-data receive lets a `MSG_OOB | MSG_PEEK` reader use an skb after a concurrent urgent send replaces and frees it.

## Prerequisites

The kernel needs `CONFIG_UNIX=y` and `CONFIG_AF_UNIX_OOB=y`. Run in the
initial user namespace as an unprivileged user with no capabilities. Multiple
CPUs improve race coverage.

## Build

```sh
make
```

The default build is static and enables compiler warnings.

## Reproduce

Copy `trigger` into the guest and run:

```sh
timeout -s KILL 180s ./trigger
```

The trigger continuously races AF_UNIX urgent sends against peek receives. It is timing-dependent and may need the full timeout or another clean-VM run.

## Expected result

KASAN reports a use-after-free in `unix_stream_read_actor`; the decisive signature is:

```text
BUG: KASAN: use-after-free in unix_stream_read_actor+0x9d/0xa0
```

Allocation and free stacks both pass through `queue_oob`.
