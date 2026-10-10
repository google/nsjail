# Security hardening notes (Patch Rewards)

## Compiler hardening (added in the hardening PR)
- -fstack-protector-strong, -D_FORTIFY_SOURCE=2 (CXXFLAGS)
- -Wl,-z,relro -Wl,-z,now (Full RELRO)
- Verified: BIND_NOW present, __stack_chk_fail referenced, jail functional.

## Fuzzing (added in the fuzzing PR)
- make asan / make fuzz-nstun / make fuzz-kafel
- fuzz/ contains both harnesses and curated seed corpora.
- kafel requires CC=clang for instrumentation; recipe included.
- The fuzz-kafel recipe forces a clean kafel rebuild before the instrumented
  build, guaranteeing the instrumented state.

## pidfd-pinned process management (proposed, not implemented)

> Note: this observation was submitted to Google's vulnerability intake
> (issuetracker 561676647) for assessment prior to this documentation;
> Google's triage directed publication through this repository. The
> unotify/io_uring observational-limits section below was included in
> the same query.



nsjail's parent performs /proc/<pid>-addressed operations on children
across the fork->handshake window using string-addressed procfs paths:
setgroups/uid_map/gid_map writes (user.cc), /proc/<pid>/syscall fd
(subproc.cc addProc), netlink set_ns_pid targeting (net.cc). A child
dying and its PID being recycled before the write targets an unrelated
process. The kernel accepts privileged uid_map writes into an unrelated
fresh user namespace under this pattern (verified experimentally).
Exploitation is blocked by signal-permission analysis in default
configurations, but the pattern is fragile by construction; runc
migrated to pidfd for this reason.

Proposal: CLONE_PIDFD in cloneProc; map writes via
/proc/self/fd/<pidfd>/uid_map; syscall-observation fd likewise;
pidfd liveness re-check before rtnl_link_set_ns_pid.

## Observational limits of --seccomp_unotify (documentation)

unotify is observational: the supervisor always responds
SECCOMP_USER_NOTIF_FLAG_CONTINUE and never denies. Syscalls issued
through io_uring are invisible (io_uring_setup/enter/register are not
in the trace table) - demonstrated: openat() via io_uring leaves no
report trace while the same openat() directly is traced.
