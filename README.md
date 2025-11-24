# NsJail

Linux process isolation tool using namespaces, resource limits, and seccomp-bpf syscall filters.

## Features

- **Multiple isolation modes**: TCP listener (inetd-style), standalone single-run, continuous re-execution
- **Namespace isolation**: UTS, MOUNT, PID, IPC, NET, USER, CGROUPS, TIME
- **Filesystem constraints**: `chroot()`, `pivot_root()`, read-only mounts, custom `/proc` and `tmpfs`
- **Resource limits**: CPU time, memory, file descriptors, process count
- **Syscall filtering**: [Kafel](https://github.com/google/kafel/) seccomp-bpf policies
- **Network isolation**: Cloned/isolated Ethernet interfaces, MACVLAN support, userland networking (pasta)
- **Cgroup integration**: Memory, PID, CPU, net_cls control (v1 and v2)
- **Configuration**: Protobuf-based config files or command-line arguments

## Installation

### Build from source

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install autoconf bison flex gcc g++ git libprotobuf-dev libnl-route-3-dev libtool make pkg-config protobuf-compiler

git clone https://github.com/google/nsjail.git
cd nsjail
make
```

### Docker

```bash
docker build -t nsjail .
docker run --privileged --rm -it nsjail nsjail --user 99999 --group 99999 --chroot / -- /bin/bash
```

## Quick Start

### Basic isolated shell

```bash
./nsjail -Mo --chroot / --user 99999 --group 99999 -- /bin/bash
```

### Network service (inetd-style)

```bash
./nsjail -Ml --port 9000 --chroot /chroot --user 99999 --group 99999 -- /bin/sh -i
```

### Re-running process (useful for fuzzing)

```bash
./nsjail -Mr --chroot / -- /bin/echo "test"
```

## Usage

### Execution Modes

| Flag | Mode | Description |
|------|------|-------------|
| `-Ml` | `LISTEN` | TCP server, fork process per connection |
| `-Mo` | `ONCE` | Execute once, exit |
| `-Me` | `EXECVE` | Direct execution without supervisor |
| `-Mr` | `RERUN` | Execute repeatedly (useful for fuzzing) |

### Common Options

```bash
# Filesystem
-c, --chroot DIR          Chroot directory (default: /)
-R, --bindmount_ro SRC    Read-only bind mount (SRC or SRC:DST)
-B, --bindmount SRC       Read-write bind mount (SRC or SRC:DST)
-T, --tmpfsmount DST      Tmpfs mount at DST
-m, --mount SRC:DST:TYPE:OPTS  Arbitrary mount

# User/Group
-u, --user UID            User ID inside jail (default: current)
-g, --group GID           Group ID inside jail (default: current)
-U, --uid_mapping I:O:C   Custom UID mapping (requires newuidmap)
-G, --gid_mapping I:O:C   Custom GID mapping (requires newgidmap)

# Namespaces
-N, --disable_clone_newnet     Disable network namespace
--disable_clone_newuser        Disable user namespace
--disable_clone_newpid         Disable PID namespace
--enable_clone_newtime         Enable time namespace (kernel >= 5.3)

# Resource Limits
-t, --time_limit SEC      Wall-time limit in seconds (default: 600)
--rlimit_as MB            Address space limit in MB
--rlimit_cpu SEC          CPU time limit in seconds
--rlimit_nofile N         Max open files

# Security
-P, --seccomp_policy FILE Seccomp-bpf policy file (Kafel syntax)
--seccomp_string POLICY   Inline seccomp policy
--cap CAP_NAME            Retain capability (can specify multiple)
--keep_caps               Retain all capabilities

# Networking
--iface_own IFACE         Move interface into jail
--macvlan_iface IFACE     Clone interface as MACVLAN
--use_pasta               Enable userland networking (pasta)

# Configuration
-C, --config FILE         Load protobuf config file
```

## Configuration Files

NsJail uses [Protocol Buffers](https://developers.google.com/protocol-buffers) for configuration. Schema: [config.proto](https://github.com/google/nsjail/blob/master/config.proto)

### Example configuration

```protobuf
name: "bash-jail"
mode: ONCE

hostname: "JAILED"
cwd: "/tmp"

time_limit: 100
max_cpus: 1

rlimit_as: 512
rlimit_cpu: 10
rlimit_nofile: 32

clone_newnet: true
clone_newuser: true
clone_newns: true
clone_newpid: true
clone_newipc: true
clone_newuts: true

uidmap {
  inside_id: "0"
  outside_id: ""
  count: 1
}

gidmap {
  inside_id: "0"
  outside_id: ""
  count: 1
}

mount {
  src: "/"
  dst: "/"
  is_bind: true
  rw: false
}

mount {
  dst: "/proc"
  fstype: "proc"
}

mount {
  dst: "/tmp"
  fstype: "tmpfs"
  rw: true
}

seccomp_string: "ALLOW { read, write, exit, exit_group } DEFAULT KILL"
```

Load with:
```bash
./nsjail --config myconfig.cfg
```

Override command:
```bash
./nsjail --config myconfig.cfg -- /usr/bin/id
```

### Example Configs

- **[bash-with-fake-geteuid.cfg](https://github.com/google/nsjail/blob/master/configs/bash-with-fake-geteuid.cfg)**: Bash with fake root UID
- **[firefox-with-net-wayland.cfg](https://github.com/google/nsjail/blob/master/configs/firefox-with-net-wayland.cfg)**: Sandboxed Firefox with networking
- **[home-documents-with-xorg-no-net.cfg](https://github.com/google/nsjail/blob/master/configs/home-documents-with-xorg-no-net.cfg)**: Document viewer with X11, no network

## Use Cases

### CTF Challenge Hosting

Isolate networked services for security challenges:
```bash
./nsjail -Ml --port 8000 \
  --chroot /srv/ctf \
  --user 65534 --group 65534 \
  --time_limit 60 \
  --rlimit_as 128 \
  --rlimit_cpu 10 \
  -- /srv/ctf/challenge
```

### Fuzzing

Continuously re-run potentially crashing programs:
```bash
./nsjail -Mr \
  --chroot / \
  --user 99999 \
  --time_limit 10 \
  --rlimit_as 512 \
  --seccomp_string 'ALLOW { ... } DEFAULT KILL' \
  -- /path/to/target @@
```

### Desktop Application Sandboxing

Run untrusted GUI applications:
```bash
./nsjail --config configs/firefox-with-net-wayland.cfg
```

### Minimal Environment Execution

Run program with minimal filesystem access:
```bash
./nsjail -Mo \
  -R /lib/x86_64-linux-gnu \
  -R /lib64 \
  -R /usr/bin/find \
  -R /dev/urandom \
  -- /usr/bin/find /
```

## Advanced Features

### Userland Networking (pasta)

Uses [pasta](https://passt.top/) for userspace networking without root privileges:

```bash
./nsjail --user 1000 --group 1000 \
  --use_pasta \
  --chroot / \
  -- /usr/bin/curl https://example.com
```

Or via config:
```protobuf
user_net {
  enable: true
  ip: "10.255.255.2"
  gw: "10.255.255.1"
  ip6: "fc00::2"
  gw6: "fc00::1"
  tcp_ports: "80,443"
  enable_dns: true
}
```

### MACVLAN Network Isolation

Clone physical interface (requires root):
```bash
sudo ./nsjail \
  --macvlan_iface eth0 \
  --macvlan_vs_ip 192.168.1.100 \
  --macvlan_vs_nm 255.255.255.0 \
  --macvlan_vs_gw 192.168.1.1 \
  -- /bin/bash
```

### Seccomp-bpf Filtering

Kafel policy syntax:
```bash
./nsjail --seccomp_string '
POLICY example {
  ALLOW {
    read, write, open, close,
    mmap, munmap, brk,
    exit_group
  }
  DEFAULT KILL
}
USE example DEFAULT KILL
' -- /bin/program
```

### Cgroups Resource Control

```bash
./nsjail \
  --cgroup_mem_max $((512*1024*1024)) \
  --cgroup_pids_max 32 \
  --cgroup_cpu_ms_per_sec 800 \
  -- /bin/cpu_intensive_program
```

## Troubleshooting

### Permission Denied Errors

1. **CLONE_NEWUSER required**: Run with `--disable_clone_newuser` (requires root) or ensure user namespaces are enabled:
   ```bash
   sysctl kernel.unprivileged_userns_clone  # Should be 1
   ```

2. **Mount errors**: Check that `/proc` is not overmounted:
   ```bash
   cat /proc/mounts | grep /proc
   ```

### Resource Not Available

Check available namespaces:
```bash
ls -la /proc/self/ns/
```

Disable unsupported namespaces (e.g., `--disable_clone_newcgroup` for kernel < 4.6).

### Debugging

Enable verbose logging:
```bash
./nsjail -v --config myconfig.cfg
```

## Documentation

- **Configuration schema**: [config.proto](https://github.com/google/nsjail/blob/master/config.proto)
- **Seccomp policies**: [Kafel documentation](https://github.com/google/kafel/)
- **Example configs**: [configs/](https://github.com/google/nsjail/tree/master/configs)

## Contact

- **Mailing list**: [nsjail@googlegroups.com](https://groups.google.com/forum/#!forum/nsjail)
- **Issues**: [GitHub Issues](https://github.com/google/nsjail/issues)

---

**This is not an official Google product.**
