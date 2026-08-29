# syzbot 5d4cb6b4409edfd18646 epoll lifetime trigger

This program reproduces the epoll file-lifetime race fixed by upstream commit
`4efaa5acf0a1` (`epoll: be better about file lifetimes`). A ready eventfd is
added to epoll, then one CPU scans the ready list while another closes the
eventfd. On a vulnerable kernel, `ep_item_poll()` can retrieve the epitem's
file after its reference count has reached zero and call `vfs_poll()` without
first acquiring a live file reference.

The original syzbot reproducer creates a dma-buf through `/dev/udmabuf`, whose
poll callback makes the dead-reference state crash-prone. This target has
neither `CONFIG_UDMABUF` nor `/dev/udmabuf`, so the stock repro never obtains
the dma-buf fd: its `epoll_ctl()` receives an invalid descriptor and a 60-second
run does not exercise the bug. The packaged trigger substitutes the built-in
eventfd poll implementation and sweeps the close timing. Eventfd does not turn
the invalid lifetime state into a reliable standalone crash, so verification
uses GDB to stop only when `ep_item_poll()` has a zero-refcount file.

## Prerequisites

- Linux without fix `4efaa5acf0a1`.
- `CONFIG_EPOLL=y` and eventfd support.
- At least two CPUs available to the process.
- A static-libc toolchain for the default build.
- For decisive verification, the target's unstripped `vmlinux` and a QEMU GDB
  stub. The address below is specific to the requested build.

No namespace or capability is required. The program refuses to run as root.

## Build and run

```sh
make
./trigger
```

For the requested `vmlinux`, start QEMU with a GDB port, then attach GDB and set
this conditional breakpoint before launching the trigger:

```gdb
set pagination off
set schedule-multiple on
target remote :20101
break *0xffffffff813e9288 if *(long*)($rdi+56)==0
continue
```

`0xffffffff813e9288` is the inlined `ep_item_poll()` site in
`do_epoll_wait()` immediately after loading `epi->ffd.file`; offset 56 is
`struct file::f_count` in this exact build. The conditional breakpoint avoids
stopping on normal live-file polls.

## Verification on the requested tree

The trigger was verified against the Linux kernel at commit
`41a7536cd0f1b11d61ea1dcfe4afbff5fa565515` (`Linux 6.1.0+`) in the existing
four-CPU, 2-GiB QEMU VM. The upstream fix applies cleanly, and the target's
`ep_item_poll()` directly reads `epi->ffd.file` and invokes `vfs_poll()` without
`atomic_long_inc_not_zero()` or `fput()`.

The process began as the ordinary account with every initial capability set
empty:

```text
initial uid=1000 euid=1000 gid=1000 egid=1000
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapAmb: 0000000000000000
```

The conditional breakpoint fired in the polling thread and showed that the
epitem still referenced exactly the same file whose count was already zero:

```text
Thread 2 hit Breakpoint 1, ep_item_poll (...)
    at fs/eventpoll.c:851
file=0xfffffe8602c19900
f_count=0
epi_file=0xfffffe8602c19900
f_op=0xffffffff82a04a20

#0 ep_item_poll
#1 ep_send_events
#2 ep_poll
#3 do_epoll_wait
#4 __do_sys_epoll_wait
#5 __se_sys_epoll_wait
#6 __x64_sys_epoll_wait
```

At that same stop, CPU 0 showed the matching file in final teardown, blocked
on the epoll mutex held by the polling CPU:

```text
#10 eventpoll_release_file(file=0xfffffe8602c19900)
#11 eventpoll_release(file=0xfffffe8602c19900)
#12 __fput(file=0xfffffe8602c19900)
#13 task_work_run
#14 resume_user_mode_work
```

Thus the poll side has no live reference (`f_count == 0`) while final
`__fput()` is already in progress on the identical pointer, yet vulnerable
`ep_item_poll()` is about to call the file's poll callback. This is decisive
source-to-dead-object evidence of the reported race. Applying `4efaa5acf0a1`
changes this path to `epi_fget()`; its `atomic_long_inc_not_zero()` fails in
this state and returns before calling `vfs_poll()`.
