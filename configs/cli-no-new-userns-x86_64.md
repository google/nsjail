# Opt-in CLI example without nested user namespaces (x86_64)

`cli-no-new-userns-x86_64.policy` is a small Kafel allowlist for native
64-bit x86 Linux command-line programs. Select it explicitly with
`--seccomp_policy`; existing configurations and their defaults are unchanged.
It is an example to adapt and validate for a specific workload, not a general
replacement for the other example policies.

Run from the repository root with an owned, disposable x86_64 root filesystem
containing `/bin/sh`, `/bin/true`, and their libraries:

```sh
./nsjail -Mo --chroot /path/to/disposable-rootfs \
  --seccomp_policy "$PWD/configs/cli-no-new-userns-x86_64.policy" \
  -- /bin/sh -c 'printf "ready\n"; /bin/true'
```

The policy is installed after NsJail sets up its own namespaces. It restricts
the jailed program's subsequent syscalls:

* `clone` and `unshare` with `CLONE_NEWUSER` return `EPERM`.
* Other `clone` and `unshare` flags pass this policy, subject to normal kernel
  permission checks. Ordinary process and thread creation are intended uses.
* All `clone3` calls return `ENOSYS`; applications need their own fallback to
  `clone`. Applications requiring clone3 will not work with this example.
* All `setns` calls return `EPERM`, including attempts to join other kinds of
  namespaces. This is a deliberate additional restriction.
* Only the listed native x86_64 syscalls are allowed. Other syscalls terminate
  the process. Network socket APIs, io_uring, mount APIs, and ptrace are not
  allowlisted. Files opened with the allowed file APIs remain subject to the
  jail's filesystem and permission restrictions.

Every rule has an `ON x86_64` guard. Compiling for another Kafel target supplies
no ALLOW rules for that target. A native x86_64 compile also rejects other audit
architectures, and x32-numbered syscalls fall through to the kill default.
This does not claim support for 32-bit executables or any foreign ABI.

Do not combine `--seccomp_policy` with `seccomp_string` in a configuration:
NsJail rejects that combination; the policies are not automatically stacked.
To adapt the allowlist, keep one policy with one default action, preserve the
conditional clone/unshare rules, and rerun native workload and ABI checks.
Adding an unconditional ALLOW for clone, unshare, or clone3 can defeat the
intended restrictions depending on rule ordering.

This example is unsuitable for browser sandboxes or workloads that need nested
user namespaces. It does not change the bundled Firefox or Chromium examples,
and it does not claim to prevent every possible namespace or kernel attack.
Validate a full NsJail launch on a Linux environment with a consistent PID
namespace and `/proc` view before using it for an actual workload.
