# syzbot 5d4cb6b4409edfd18646

## Summary

A race in epoll file-lifetime handling can call a poll callback after the watched file reaches final teardown. The trigger uses a dma-buf from `/dev/udmabuf` to reach the faulty lifetime transition.

## Target

Linux 6.1 at commit `830b3c68c1fb1e9176028d02ef86f3cf76aa2476`. Required configuration: `CONFIG_EPOLL=y`, `CONFIG_DMA_SHARED_BUFFER=y`, and `CONFIG_UDMABUF=y`.

## Prerequisites

The `/dev/udmabuf` device node must exist and be readable and writable by the invoking user; an administrator may need to adjust its mode before the run. The trigger itself runs in the initial user namespace as an ordinary user and needs no capability. The verified run used uid 1000 with all capability sets empty.

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

## Verified result

Verified on a clean target VM as uid 1000 with no capabilities. The trigger produced the expected KASAN null-pointer finding at `__fput+0x188/0x880` and a fatal kernel panic; the fresh raw serial excerpt is in `runtime-console.txt`.
