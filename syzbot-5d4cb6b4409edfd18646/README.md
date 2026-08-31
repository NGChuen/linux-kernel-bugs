# syzbot 5d4cb6b4409edfd18646

## Summary

A race in epoll file-lifetime handling can call a poll callback after the watched file reaches final teardown. The trigger uses a dma-buf from `/dev/udmabuf` to reach the faulty lifetime transition.

## Prerequisites

The kernel needs `CONFIG_EPOLL=y`, `CONFIG_DMA_SHARED_BUFFER=y`, and
`CONFIG_UDMABUF=y`. The `/dev/udmabuf` device node must exist and be readable
and writable by the invoking user; an administrator may need to adjust its
mode before the run. The trigger itself runs in the initial user namespace as
an unprivileged user with no capabilities.

## Build

```sh
make
```

The default build is static and enables compiler warnings.

## Reproduce

Copy `trigger` into the guest, make `/dev/udmabuf` accessible as described above, and run:

```sh
timeout -s KILL 180s ./trigger
```

The trigger repeatedly races epoll scanning with file teardown. It is timing-dependent; a failure normally occurs quickly, but a clean-VM retry may be required before the timeout.

## Expected result

KASAN diagnoses a low-address dereference during final file teardown. On this build the decisive signature is:

```text
KASAN: null-ptr-deref in range [0x0000000000000028-0x000000000000002f]
RIP: 0010:__fput+0x188/0x880
```
