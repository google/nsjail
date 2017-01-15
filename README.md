- [WHAT IS IT?](#what-is-it-)
- [WHAT TYPE OF ISOLATION DOES THIS TOOL PROVIDE?](#what-type-of-isolation-does-this-tool-provide-)
- [WHICH USE-CASES ARE SUPPORTED?](#which-use-cases-are-supported-)
  * [Isolation of network services (inetd-style)](#isolation-of-network-services--inetd-style-)
  * [Isolation, with access to a private, cloned interface (requires euid==0)](#isolation--with-access-to-a-private--cloned-interface--requires-euid--0-)
  * [Isolation of local processes](#isolation-of-local-processes)
  * [Isolation of local processes (and re-running them)](#isolation-of-local-processes--and-re-running-them-)
  * [Bash in a minimal file-system with uid==0 and access to /dev/urandom](#bash-in-a-minimal-file-system-with-uid--0-and-access-to--dev-urandom)
  * [Even more contrained shell (with seccomp-bpf policies)](#even-more-contrained-shell--with-seccomp-bpf-policies-)
- [MORE INFO?](#more-info-)

### WHAT IS IT?
NsJail is a process isolation tool for Linux. It makes use of the the namespacing, resource control, and seccomp-bpf syscall filter subsystems of the Linux kernel.

It can help, among others, with:
  * Securing networking services (e.g. web, time, DNS), by isolating them from the rest of the OS
  * Hosting computer security challenges (so-called CTFs)
  * Containing invasive syscall-level OS fuzzers

This is NOT an official Google product.

### WHAT TYPE OF ISOLATION DOES THIS TOOL PROVIDE?
1. Linux namespaces: UTS (hostname), MOUNT (chroot), PID (separate PID tree), IPC, NET (separate networking context), USER
2. FS constraints: chroot(), pivot_root(), RO-remounting
3. Resource limits (wall-time/CPU time limits, VM/mem address space limits, etc.)
4. Programmable seccomp-bpf syscall filters
5. Cloned and separated Ethernet interfaces
6. Cgroups for memory utilization control

### WHICH USE-CASES ARE SUPPORTED?
#### Isolation of network services (inetd-style)

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

#### Isolation, with access to a private, cloned interface (requires euid==0)
```
$ sudo ./nsjail --user 9999 --group 9999 --iface eth0 --chroot /chroot/ -Mo --iface_vs_ip 192.168.0.44 --iface_vs_nm 255.255.255.0 --iface_vs_gw 192.168.0.1 -- /bin/sh -i
/ $ id
uid=9999 gid=9999
/ $ ip addr sh
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: vs: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue 
    link/ether ca:a2:69:21:33:66 brd ff:ff:ff:ff:ff:ff
    inet 192.168.0.44/24 brd 192.168.0.255 scope global vs
       valid_lft forever preferred_lft forever
    inet6 fe80::c8a2:69ff:fe21:cd66/64 scope link 
       valid_lft forever preferred_lft forever
/ $ nc 217.146.165.209 80
GET / HTTP/1.0

HTTP/1.0 302 Found
Cache-Control: private
Content-Type: text/html; charset=UTF-8
Location: http://www.google.ch/?gfe_rd=cr&ei=cEzWVrG2CeTI8ge88ofwDA
Content-Length: 258
Date: Wed, 02 Mar 2016 02:14:08 GMT

<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>302 Moved</TITLE></HEAD><BODY>
<H1>302 Moved</H1>
The document has moved
<A HREF="http://www.google.ch/?gfe_rd=cr&amp;ei=cEzWVrG2CeTI8ge88ofwDA">here</A>.
</BODY></HTML>
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

#### Bash in a minimal file-system with uid==0 and access to /dev/urandom
```
$ ./nsjail -Mo --user 0 --group 99999 -R /bin/ -R /lib -R /lib64/ -R /usr/ -R /sbin/ -T /dev -R /dev/urandom --keep_caps -- /bin/bash -i
bash-4.3# ls -l /
total 40
drwxr-xr-x   2 65534 65534 12288 Jun 17 23:27 bin
drwxrwxrwt   2     0 99999    60 Jun 19 12:31 dev
drwxr-xr-x  25 65534 65534  4096 Jun  9 18:29 lib
drwxr-xr-x   2 65534 65534  4096 Apr 15 22:27 lib64
dr-xr-xr-x 260 65534 65534     0 Jun 19 12:31 proc
drwxr-xr-x   2 65534 65534 16384 Jun 11 21:03 sbin
drwxr-xr-x  21 65534 65534  4096 Apr 24 16:13 usr
bash-4.3# ls -l /dev/
total 0
crw-rw-rw- 1 65534 65534 1, 9 Jun  9 18:33 urandom
bash-4.3# id
uid=0 gid=99999 groups=99999,65534
```

#### Even more contrained shell (with seccomp-bpf policies)
```
$ ./nsjail --chroot / --seccomp_string 'POLICY a { ALLOW { write, execve, brk, access, mmap, open, newfstat, close, read, mprotect, arch_prctl, munmap, getuid, getgid, getpid, rt_sigaction, geteuid, getppid, getcwd, getegid, ioctl, fcntl, newstat, clone, wait4, rt_sigreturn, exit_group } } USE a DEFAULT KILL' -- /bin/sh -i
[2017-01-15T21:53:08+0100] Mode: STANDALONE_ONCE
[2017-01-15T21:53:08+0100] Jail parameters: hostname:'NSJAIL', chroot:'/', process:'/bin/sh', bind:[::]:0, max_conns_per_ip:0, uid:(ns:1000, global:1000), gid:(ns:1000, global:1000), time_limit:0, personality:0, daemonize:false, clone_newnet:true, clone_newuser:true, clone_newns:true, clone_newpid:true, clone_newipc:true, clonew_newuts:true, clone_newcgroup:false, keep_caps:false, tmpfs_size:4194304, disable_no_new_privs:false, pivot_root_only:false
[2017-01-15T21:53:08+0100] Mount point: src:'/' dst:'/' type:'' flags:0x5001 options:''
[2017-01-15T21:53:08+0100] Mount point: src:'(null)' dst:'/proc' type:'proc' flags:0x0 options:''
[2017-01-15T21:53:08+0100] PID: 18873 about to execute '/bin/sh' for [STANDALONE_MODE]
/bin/sh: 0: can't access tty; job control turned off
$ set
IFS='
'
OPTIND='1'
PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
PPID='0'
PS1='$ '
PS2='> '
PS4='+ '
PWD='/'
$ id
Bad system call
$ exit
[2017-01-15T21:53:17+0100] PID: 18873 exited with status: 159, (PIDs left: 0)
```

### MORE INFO?
To see the options, simply type:
```
./nsjail --help
```

The commandline options should be reasonably well-documented

```
Usage: ./nsjail [options] -- path_to_command [args]
Options:
 --help|-h 
	Help plz..
 --mode|-M VALUE
	Execution mode (default: o [MODE_STANDALONE_ONCE]):
	l: Wait for connections on a TCP port (specified with --port) [MODE_LISTEN_TCP]
	o: Immediately launch a single process on a console using clone/execve [MODE_STANDALONE_ONCE]
	e: Immediately launch a single process on a console using execve [MODE_STANDALONE_EXECVE]
	r: Immediately launch a single process on a console, keep doing it forever [MODE_STANDALONE_RERUN]
 --chroot|-c VALUE
	Directory containing / of the jail (default: none)
 --rw 
	Mount / as RW (default: RO)
 --user|-u VALUE
	Username/uid of processess inside the jail (default: your current uid). You can also use inside_ns_uid:outside_ns_uid convention here
 --group|-g VALUE
	Groupname/gid of processess inside the jail (default: your current gid). You can also use inside_ns_gid:global_ns_gid convention here
 --hostname|-H VALUE
	UTS name (hostname) of the jail (default: 'NSJAIL')
 --cwd|-D VALUE
	Directory in the namespace the process will run (default: '/')
 --port|-p VALUE
	TCP port to bind to (enables MODE_LISTEN_TCP) (default: 0)
 --bindhost VALUE
	IP address port to bind to (only in [MODE_LISTEN_TCP]), '::ffff:127.0.0.1' for locahost (default: '::')
 --max_conns_per_ip|-i VALUE
	Maximum number of connections per one IP (default: 0 (unlimited))
 --log|-l VALUE
	Log file (default: /proc/self/fd/2)
 --time_limit|-t VALUE
	Maximum time that a jail can exist, in seconds (default: 600)
 --daemon|-d 
	Daemonize after start
 --verbose|-v 
	Verbose output
 --keep_env|-e 
	Should all environment variables be passed to the child?
 --env|-E VALUE
	Environment variable (can be used multiple times)
 --keep_caps 
	Don't drop capabilities (DANGEROUS)
 --silent 
	Redirect child's fd:0/1/2 to /dev/null
 --skip_setsid 
	Don't call setsid(), allows for terminal signal handling in the sandboxed process
 --pass_fd VALUE
	Don't close this FD before executing child (can be specified multiple times), by default: 0/1/2 are kept open
 --pivot_root_only 
	Only perform pivot_root, no chroot. This will enable nested namespaces
 --disable_no_new_privs 
	Don't set the prctl(NO_NEW_PRIVS, 1) (DANGEROUS)
 --rlimit_as VALUE
	RLIMIT_AS in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 512)
 --rlimit_core VALUE
	RLIMIT_CORE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 0)
 --rlimit_cpu VALUE
	RLIMIT_CPU, 'max' for RLIM_INFINITY, 'def' for the current value (default: 600)
 --rlimit_fsize VALUE
	RLIMIT_FSIZE in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 1)
 --rlimit_nofile VALUE
	RLIMIT_NOFILE, 'max' for RLIM_INFINITY, 'def' for the current value (default: 32)
 --rlimit_nproc VALUE
	RLIMIT_NPROC, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')
 --rlimit_stack VALUE
	RLIMIT_STACK in MB, 'max' for RLIM_INFINITY, 'def' for the current value (default: 'def')
 --persona_addr_compat_layout 
	personality(ADDR_COMPAT_LAYOUT)
 --persona_mmap_page_zero 
	personality(MMAP_PAGE_ZERO)
 --persona_read_implies_exec 
	personality(READ_IMPLIES_EXEC)
 --persona_addr_limit_3gb 
	personality(ADDR_LIMIT_3GB)
 --persona_addr_no_randomize 
	personality(ADDR_NO_RANDOMIZE)
 --disable_clone_newnet|-N 
	Don't use CLONE_NEWNET. Enable networking inside the jail
 --disable_clone_newuser 
	Don't use CLONE_NEWUSER. Requires euid==0
 --disable_clone_newns 
	Don't use CLONE_NEWNS
 --disable_clone_newpid 
	Don't use CLONE_NEWPID
 --disable_clone_newipc 
	Don't use CLONE_NEWIPC
 --disable_clone_newuts 
	Don't use CLONE_NEWUTS
 --enable_clone_newcgroup 
	Use CLONE_NEWCGROUP
 --uid_mapping|-U VALUE
	Add a custom uid mapping of the form inside_uid:outside_uid:count. Setting this requires newuidmap to be present
 --gid_mapping|-G VALUE
	Add a custom gid mapping of the form inside_gid:outside_gid:count. Setting this requires newuidmap to be present
 --bindmount_ro|-R VALUE
	List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'
 --bindmount|-B VALUE
	List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'
 --tmpfsmount|-T VALUE
	List of mountpoints to be mounted as RW/tmpfs inside the container. Can be specified multiple times. Supports 'dest' syntax
 --tmpfs_size VALUE
	Number of bytes to allocate for tmpfsmounts (default: 4194304)
 --disable_proc 
	Disable mounting /proc in the jail
 --seccomp_policy|-P VALUE
	Path to file containing seccomp-bpf policy (see kafel/)
 --seccomp_string VALUE
	String with kafel seccomp-bpf policy (see kafel/)
 --cgroup_mem_max VALUE
	Maximum number of bytes to use in the group (default: '0' - disabled)
 --cgroup_mem_mount VALUE
	Location of memory cgroup FS (default: '/sys/fs/cgroup/memory')
 --cgroup_mem_parent VALUE
	Which pre-existing memory cgroup to use as a parent (default: 'NSJAIL')
 --iface_no_lo 
	Don't bring up the 'lo' interface
 --iface|-I VALUE
	Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'
 --iface_vs_ip VALUE
	IP of the 'vs' interface
 --iface_vs_nm VALUE
	Netmask of the 'vs' interface
 --iface_vs_gw VALUE
	Default GW for the 'vs' interface

 Examples: 
 Wait on a port 31337 for connections, and run /bin/sh
  nsjail -Ml --port 31337 --chroot / -- /bin/sh -i
 Re-run echo command as a sub-process
  nsjail -Mr --chroot / -- /bin/echo "ABC"
 Run echo command once only, as a sub-process
  nsjail -Mo --chroot / -- /bin/echo "ABC"
 Execute echo command directly, without a supervising process
  nsjail -Me --chroot / --disable_proc -- /bin/echo "ABC"
```
