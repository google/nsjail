### WHAT IS IT?
NsJail is a process isolation tool for Linux. It makes use of the the namespacing, resource control, and seccomp-bpf syscall filter subsystems of the Linux kernel.

It can help, among others, with:
  * Securing networking services (e.g. web, time, DNS), by isolating them from the rest of the OS
  * Hosting computer security challenges (so-called CTFs)
  * Containing invasive syscall-level OS fuzzers

This is NOT an official Google product.

### WHAT KIND OF ISOLATION DOES IT PROVIDE?
1. Linux namespaces: UTS (hostname), MOUNT (chroot), PID (separate PID tree), IPC, NET (separate networking context), USER
2. FS constraints: chroot(), pivot_root(), RO-remounting
3. Resource limits (wall-time/CPU time limits, VM/mem address space limits, etc.)
4. Programmable seccomp-bpf syscall filters

### WHICH USE-CASES ARE COVERED?
#### Isolation of network servers (inetd-style)

+ Server:
```
 $ ./nsjail -Ml --port 9000 --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i
```

+ Client:
```
 $ nc 127.0.0.1 9000
 / $ ifconfig
 / $ ifconfig -a
 lo    Link encap:Local Loopback
       LOOPBACK  MTU:65536  Metric:1
       RX packets:0 errors:0 dropped:0 overruns:0 frame:0
       TX packets:0 errors:0 dropped:0 overruns:0 carrier:0 collisions:0 txqueuelen:0
       RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
 / $ ps wuax
 PID   USER     COMMAND
 1 99999    /bin/sh -i
 3 99999    {busybox} ps wuax
 / $

```

#### Isolation of local processes
```
 $ ./nsjail -Mo --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i
 / $ ifconfig -a
 lo    Link encap:Local Loopback
       LOOPBACK  MTU:65536  Metric:1
       RX packets:0 errors:0 dropped:0 overruns:0 frame:0
       TX packets:0 errors:0 dropped:0 overruns:0 carrier:0 collisions:0 txqueuelen:0
       RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
 / $ id
 uid=99999 gid=99999
 / $ ps wuax
 PID   USER     COMMAND
 1 99999    /bin/sh -i
 4 99999    {busybox} ps wuax
 / $exit
 $
```

#### Isolation of local processes (and re-running them)
```
 $ ./nsjail -Mr --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i
 BusyBox v1.21.1 (Ubuntu 1:1.21.0-1ubuntu1) built-in shell (ash)
 Enter 'help' for a list of built-in commands.
 / $ ps wuax
 PID   USER     COMMAND
 1 99999    /bin/sh -i
 2 99999    {busybox} ps wuax
 / $ exit
 BusyBox v1.21.1 (Ubuntu 1:1.21.0-1ubuntu1) built-in shell (ash)
 Enter 'help' for a list of built-in commands.
 / $ ps wuax
 PID   USER     COMMAND
 1 99999    /bin/sh -i
 2 99999    {busybox} ps wuax
 / $
```

### MORE INFO?
Type:
```
./nsjail --help'
```
The commandline options are reasonably well-documented
```
Usage: ./nsjail [options] -- path_to_command [args]
Options:
 --help|-h
	Help plz..
 --mode|-M [val]
	Execution mode (default: l [MODE_LISTEN_TCP]):
	l: Listen to connections on a TCP port (specified with --port) [MODE_LISTEN_TCP]
	o: Immediately launch a single process on a console [MODE_STANDALONE_ONCE]
	r: Immediately launch a single process on a console, keep doing it forever [MODE_STANDALONE_RERUN]
 --chroot|-c [val]
	Directory containing / of the jail (default: '/chroot')
 --user|-u [val]
	Username/uid of processess inside the jail (default: 'nobody')
 --group|-g [val]
	Groupname/gid of processess inside the jail (default: 'nogroup')
 --hostname|-H [val]
	UTS name (hostname) of the jail (default: 'NSJAIL')
 --cwd|-D [val]
    Directory in the namespace the process will run (default: '/')
 --port|-p [val]
	TCP port to bind to (only in [MODE_LISTEN_TCP]) (default: 31337)
 --max_conns_per_ip|-i [val]
	Maximum number of connections per one IP (default: 0 (unlimited))
 --log|-l [val]
	Log file (default: stderr)
 --time_limit|-t [val]
	Maximum time that a jail can exist, in seconds (default: 600)
 --daemon|-d
 --verbose|-v
	Verbose output (default: false)
 --keep_env|-e
	Should all environment variables be passed to the child? (default: false)
 --keep_caps
	Don't drop capabilities (DANGEROUS) (default: false)
 --rlimit_as [val]
	RLIMIT_AS in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 512)
 --rlimit_core [val]
	RLIMIT_CORE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 0)
 --rlimit_cpu [val]
	RLIMIT_CPU, 'max' for RLIM_INFINITY, 'def' for the current value (default: 600)
 --rlimit_fsize [val]
	RLIMIT_FSIZE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 1)
 --rlimit_nofile [val]
	RLIMIT_NOFILE, 'max' for RLIM_INFINITY, 'def' for the current value (default: 32)
 --rlimit_nproc [val]
	RLIMIT_NPROC, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')
 --rlimit_stack [val]
	RLIMIT_STACK in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')
 --persona_addr_compat_layout
	personality(ADDR_COMPAT_LAYOUT) (default: false)
 --persona_mmap_page_zero
	personality(MMAP_PAGE_ZERO) (default: false)
 --persona_read_implies_exec
	personality(READ_IMPLIES_EXEC) (default: false)
 --persona_addr_limit_3gb
	personality(ADDR_LIMIT_3GB) (default: false)
 --persona_addr_no_randomize
	personality(ADDR_NO_RANDOMIZE) (default: false)
 --disable_clone_newnet|-N
	Enable networking inside the jail (default: false)
 --disable_clone_newuser
	Don't use CLONE_NEWUSER (default: false)
 --disable_clone_newns
	Don't use CLONE_NEWNS (default: false)
 --disable_clone_newpid
	Don't use CLONE_NEWPID (default: false)
 --disable_clone_newipc
	Don't use CLONE_NEWIPC (default: false)
 --disable_clone_newuts
	Don't use CLONE_NEWUTS (default: false)
 --disable_sandbox
	Don't enable the seccomp-bpf sandboxing (default: false)
 --rw
	Mount / as RW (default: RO)
 --silent
	Redirect child's fd:0/1/2 to /dev/null (default: false)
 --bindmount_ro [val]
	List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'. (default: none)
 --bindmount|-B [val]
	List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'. (default: none)
 --tmpfsmount|-T [val]
	List of mountpoints to be mounted as RW/tmpfs inside the container. Can be specified multiple times. Supports 'dest' syntax. (default: none)
 --iface|-I [val]
	Interface which will be cloned (MACVTAP) and put inside the subprocess' namespace
 --tmpfs_size [val]
	Number of bytes to allocate for tmpfsmounts in bytes (default: 4194304)
```
