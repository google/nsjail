- [Overview](#overview)
- [What forms of isolation does it provide](#what-forms-of-isolation-does-it-provide)
- Which use-cases are supported
  * [Isolation of network services (inetd style)](#isolation-of-network-services-inetd-style)
  * [Isolation with access to a private, cloned interface (requires root/setuid)](#isolation-with-access-to-a-private-cloned-interface-requires-rootsetuid)
  * [Isolation of local processes](#isolation-of-local-processes)
  * [Isolation of local processes (and re-running them, if necessary)](#isolation-of-local-processes-and-re-running-them-if-necessary)
- Examples of use
  * [Bash in a minimal file-system with uid==0 and access to /dev/urandom only](#bash-in-a-minimal-file-system-with-uid0-and-access-to-devurandom-only)
  * [/usr/bin/find in a minimal file-system (only /usr/bin/find accessible from /usr/bin)](#usrbinfind-in-a-minimal-file-system-only-usrbinfind-accessible-from-usrbin)
  * [Using /etc/subuid](#using-etcsubuid)
  * [Even more contrained shell (with seccomp-bpf policies)](#even-more-contrained-shell-with-seccomp-bpf-policies)
- [Configuration file](#configuration-file)
- [More info](#more-info)
- [Launching in Docker](#launching-in-docker)
- [Contact](#contact)

***
This is NOT an official Google product.

***

### Overview
NsJail is a process isolation tool for Linux. It utilizes Linux namespace subsystem, resource limits, and the seccomp-bpf syscall filters of the Linux kernel.

It can help you with (among other things):
  * Isolating __networking services__ (e.g. web, time, DNS), by isolating them from the rest of the OS
  * Hosting computer security challenges (so-called __CTFs__)
  * Containing invasive syscall-level OS __fuzzers__

Features:
  - [x]  Offers three __distinct operational modes__. See [this section](#which-use-cases-are-supported) for more info.
  - [x]  Utilizes [kafel seccomp-bpf configuration language](https://github.com/google/kafel/) for __flexible syscall policy definitions__.
  - [x]  Uses expressive, ProtoBuf-based [configuration file](#configuration-file)
  - [x]  It's __rock-solid__.

***
### What forms of isolation does it provide
1. Linux __namespaces__: UTS (hostname), MOUNT (chroot), PID (separate PID tree), IPC, NET (separate networking context), USER, CGROUPS
2. __FS constraints__: chroot(), pivot_root(), RO-remounting, custom ```/proc``` and ```tmpfs``` mount points
3. __Resource limits__ (wall-time/CPU time limits, VM/mem address space limits, etc.)
4. Programmable seccomp-bpf __syscall filters__ (through the [kafel language](https://github.com/google/kafel/))
5. Cloned and isolated __Ethernet interfaces__
6. __Cgroups__ for memory and PID utilization control

***
### Which use-cases are supported
#### Isolation of network services (inetd style)

_PS: You'll need to have a valid file-system tree in ```/chroot```. If you don't have it, change ```/chroot``` to ```/```_

+ Server:
<pre>
 $ ./nsjail -Ml --port 9000 --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i
</pre>

+ Client:
<pre>
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

</pre>

#### Isolation with access to a private, cloned interface (requires root/setuid)

_PS: You'll need to have a valid file-system tree in ```/chroot```. If you don't have it, change ```/chroot``` to ```/```_

<pre>
$ sudo ./nsjail --user 9999 --group 9999 --macvlan_iface eth0 --chroot /chroot/ -Mo --macvlan_vs_ip 192.168.0.44 --macvlan_vs_nm 255.255.255.0 --macvlan_vs_gw 192.168.0.1 -- /bin/sh -i
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
Location: https://www.google.ch/?gfe_rd=cr&ei=cEzWVrG2CeTI8ge88ofwDA
Content-Length: 258
Date: Wed, 02 Mar 2016 02:14:08 GMT

...
...
/ $ 
</pre>

#### Isolation of local processes

_PS: You'll need to have a valid file-system tree in ```/chroot```. If you don't have it, change ```/chroot``` to ```/```_

<pre>
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
</pre>

#### Isolation of local processes (and re-running them, if necessary)

_PS: You'll need to have a valid file-system tree in ```/chroot```. If you don't have it, change ```/chroot``` to ```/```_

<pre>
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
</pre>

### Bash in a minimal file-system with uid==0 and access to /dev/urandom only

<pre>
$ ./nsjail -Mo --user 0 --group 99999 -R /bin/ -R /lib -R /lib64/ -R /usr/ -R /sbin/ -T /dev -R /dev/urandom --keep_caps -- /bin/bash -i
[2017-05-24T17:08:02+0200] Mode: STANDALONE_ONCE
[2017-05-24T17:08:02+0200] Jail parameters: hostname:'NSJAIL', chroot:'(null)', process:'/bin/bash', bind:[::]:0, max_conns_per_ip:0, time_limit:0, personality:0, daemonize:false, clone_newnet:true, clone_newuser:true, clone_newns:true, clone_newpid:true, clone_newipc:true, clonew_newuts:true, clone_newcgroup:false, keep_caps:true, tmpfs_size:4194304, disable_no_new_privs:false, pivot_root_only:false
[2017-05-24T17:08:02+0200] Mount point: src:'none' dst:'/' type:'tmpfs' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'none' dst:'/proc' type:'proc' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/bin/' dst:'/bin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/lib' dst:'/lib' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/lib64/' dst:'/lib64/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/usr/' dst:'/usr/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/sbin/' dst:'/sbin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'none' dst:'/dev' type:'tmpfs' flags:0 options:'size=4194304' isDir:True
[2017-05-24T17:08:02+0200] Mount point: src:'/dev/urandom' dst:'/dev/urandom' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:False
[2017-05-24T17:08:02+0200] Uid map: inside_uid:0 outside_uid:69664
[2017-05-24T17:08:02+0200] Gid map: inside_gid:99999 outside_gid:5000
[2017-05-24T17:08:02+0200] Executing '/bin/bash' for '[STANDALONE_MODE]'
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.3# ls -l
total 28
drwxr-xr-x   2 65534 65534  4096 May 15 14:04 bin
drwxrwxrwt   2     0 99999    60 May 24 15:08 dev
drwxr-xr-x  28 65534 65534  4096 May 15 14:10 lib
drwxr-xr-x   2 65534 65534  4096 May 15 13:56 lib64
dr-xr-xr-x 391 65534 65534     0 May 24 15:08 proc
drwxr-xr-x   2 65534 65534 12288 May 15 14:16 sbin
drwxr-xr-x  17 65534 65534  4096 May 15 13:58 usr
bash-4.3# id
uid=0 gid=99999 groups=65534,99999
bash-4.3# exit
exit
[2017-05-24T17:08:05+0200] PID: 129839 exited with status: 0, (PIDs left: 0)
</pre>

### /usr/bin/find in a minimal file-system (only /usr/bin/find accessible from /usr/bin)

<pre>
$ ./nsjail -Mo --user 99999 --group 99999 -R /lib/x86_64-linux-gnu/ -R /lib/x86_64-linux-gnu -R /lib64 -R /usr/bin/find -R /dev/urandom --keep_caps -- /usr/bin/find / | wc -l
[2017-05-24T17:04:37+0200] Mode: STANDALONE_ONCE
[2017-05-24T17:04:37+0200] Jail parameters: hostname:'NSJAIL', chroot:'(null)', process:'/usr/bin/find', bind:[::]:0, max_conns_per_ip:0, time_limit:0, personality:0, daemonize:false, clone_newnet:true, clone_newuser:true, clone_newns:true, clone_newpid:true, clone_newipc:true, clonew_newuts:true, clone_newcgroup:false, keep_caps:true, tmpfs_size:4194304, disable_no_new_privs:false, pivot_root_only:false
[2017-05-24T17:04:37+0200] Mount point: src:'none' dst:'/' type:'tmpfs' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:04:37+0200] Mount point: src:'none' dst:'/proc' type:'proc' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:04:37+0200] Mount point: src:'/lib/x86_64-linux-gnu/' dst:'/lib/x86_64-linux-gnu/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:04:37+0200] Mount point: src:'/lib/x86_64-linux-gnu' dst:'/lib/x86_64-linux-gnu' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:04:37+0200] Mount point: src:'/lib64' dst:'/lib64' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:04:37+0200] Mount point: src:'/usr/bin/find' dst:'/usr/bin/find' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:False
[2017-05-24T17:04:37+0200] Mount point: src:'/dev/urandom' dst:'/dev/urandom' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:False
[2017-05-24T17:04:37+0200] Uid map: inside_uid:99999 outside_uid:69664
[2017-05-24T17:04:37+0200] Gid map: inside_gid:99999 outside_gid:5000
[2017-05-24T17:04:37+0200] Executing '/usr/bin/find' for '[STANDALONE_MODE]'
/usr/bin/find: `/proc/tty/driver': Permission denied
2289
[2017-05-24T17:04:37+0200] PID: 129525 exited with status: 1, (PIDs left: 0)
</pre>

### Using /etc/subuid

<pre>
$ tail -n1 /etc/subuid
user:10000000:1
$ ./nsjail -R /lib -R /lib64/ -R /usr/lib -R /usr/bin/ -R /usr/sbin/ -R /bin/ -R /sbin/ -R /dev/null -U 0:10000000:1 -u 0 -R /tmp/ -T /tmp/ -- /bin/ls -l /usr/
[2017-05-24T17:12:31+0200] Mode: STANDALONE_ONCE
[2017-05-24T17:12:31+0200] Jail parameters: hostname:'NSJAIL', chroot:'(null)', process:'/bin/ls', bind:[::]:0, max_conns_per_ip:0, time_limit:0, personality:0, daemonize:false, clone_newnet:true, clone_newuser:true, clone_newns:true, clone_newpid:true, clone_newipc:true, clonew_newuts:true, clone_newcgroup:false, keep_caps:false, tmpfs_size:4194304, disable_no_new_privs:false, pivot_root_only:false
[2017-05-24T17:12:31+0200] Mount point: src:'none' dst:'/' type:'tmpfs' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'none' dst:'/proc' type:'proc' flags:MS_RDONLY|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/lib' dst:'/lib' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/lib64/' dst:'/lib64/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/usr/lib' dst:'/usr/lib' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/usr/bin/' dst:'/usr/bin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/usr/sbin/' dst:'/usr/sbin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/bin/' dst:'/bin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/sbin/' dst:'/sbin/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'/dev/null' dst:'/dev/null' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:False
[2017-05-24T17:12:31+0200] Mount point: src:'/tmp/' dst:'/tmp/' type:'' flags:MS_RDONLY|MS_BIND|MS_REC|0 options:'' isDir:True
[2017-05-24T17:12:31+0200] Mount point: src:'none' dst:'/tmp/' type:'tmpfs' flags:0 options:'size=4194304' isDir:True
[2017-05-24T17:12:31+0200] Uid map: inside_uid:0 outside_uid:69664
[2017-05-24T17:12:31+0200] Gid map: inside_gid:5000 outside_gid:5000
[2017-05-24T17:12:31+0200] Newuid mapping: inside_uid:'0' outside_uid:'10000000' count:'1'
[2017-05-24T17:12:31+0200] Executing '/bin/ls' for '[STANDALONE_MODE]'
total 120
drwxr-xr-x   5 65534 65534 77824 May 24 12:25 bin
drwxr-xr-x 210 65534 65534 20480 May 22 16:11 lib
drwxr-xr-x   4 65534 65534 20480 May 24 00:24 sbin
[2017-05-24T17:12:31+0200] PID: 130841 exited with status: 0, (PIDs left: 0)
</pre>

### Even more contrained shell (with seccomp-bpf policies)

<pre>
$ ./nsjail --chroot / --seccomp_string 'ALLOW { write, execve, brk, access, mmap, open, openat, newfstat, close, read, mprotect, arch_prctl, munmap, getuid, getgid, getpid, rt_sigaction, geteuid, getppid, getcwd, getegid, ioctl, fcntl, newstat, clone, wait4, rt_sigreturn, exit_group } DEFAULT KILL' -- /bin/sh -i
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
</pre>

***
### Configuration file

You will also find all examples in the [configs](https://github.com/google/nsjail/blob/master/configs) directory.

***

[config.proto](https://github.com/google/nsjail/blob/master/config.proto) contains ProtoBuf schema for nsjail's configuration format.

***

You can examine an example config file in [configs/bash-with-fake-geteuid.cfg](https://github.com/google/nsjail/blob/master/configs/bash-with-fake-geteuid.cfg).

Usage:
<pre>
$ ./nsjail --config configs/bash-with-fake-geteuid.cfg
</pre>

You can also override certain options with command-line options. Here, the executed binary (_/bin/bash_) is overriden with _/usr/bin/id_, yet options from _configs/bash-with-fake-geteuid.cfg_ still apply
<pre>
$ ./nsjail --config configs/bash-with-fake-geteuid.cfg -- /usr/bin/id
...
[INSIDE-JAIL]: id
uid=999999 gid=999998 euid=4294965959 groups=999998,65534
[INSIDE-JAIL]: exit
[2017-05-27T18:45:40+0200] PID: 16579 exited with status: 0, (PIDs left: 0)
</pre>

***

You might also want to try using [configs/home-documents-with-xorg-no-net.cfg](https://github.com/google/nsjail/blob/master/configs/home-documents-with-xorg-no-net.cfg).

<pre>
$ ./nsjail --config configs/home-documents-with-xorg-no-net.cfg -- /usr/bin/evince /user/Documents/doc.pdf
$ ./nsjail --config configs/home-documents-with-xorg-no-net.cfg -- /usr/bin/geeqie /user/Documents/
$ ./nsjail --config configs/home-documents-with-xorg-no-net.cfg -- /usr/bin/gv /user/Documents/doc.pdf
$ ./nsjail --config configs/home-documents-with-xorg-no-net.cfg -- /usr/bin/mupdf /user/Documents/doc.pdf
</pre>

***

The [configs/firefox-with-net.cfg](https://github.com/google/nsjail/blob/master/configs/firefox-with-net.cfg)
config file will allow you to run firefox inside a sandboxed environment:

<pre>
$ ./nsjail --config configs/firefox-with-net.cfg
</pre>

A more complex setup, which utilizes virtualized (cloned) Ethernet
interfaces (to separate it from the main network namespace), can be
found in [configs/firefox-with-cloned-net.cfg](https://github.com/google/nsjail/blob/master/configs/firefox-with-cloned-net.cfg).
Remember to change relevant UIDs and Ethernet interface names before use.

As using cloned Ethernet interfaces (MACVTAP) required root privileges, you'll
have to run it under sudo:

<pre>
$ sudo ./nsjail --config configs/firefox-with-cloned-net.cfg
</pre>

***
### More info

The command-line options should be self-explanatory, while the proto-buf config options are described in [config.proto](https://github.com/google/nsjail/blob/master/config.proto)

<pre>
./nsjail --help
</pre>

<pre>
Usage: ./nsjail [options] -- path_to_command [args]
Options:
 --help|-h 
	Help plz..
 --mode|-M VALUE
	Execution mode (default: 'o' [MODE_STANDALONE_ONCE]):
	l: Wait for connections on a TCP port (specified with --port) [MODE_LISTEN_TCP]
	o: Launch a single process on the console using clone/execve [MODE_STANDALONE_ONCE]
	e: Launch a single process on the console using execve [MODE_STANDALONE_EXECVE]
	r: Launch a single process on the console with clone/execve, keep doing it forever [MODE_STANDALONE_RERUN]
 --config|-C VALUE
	Configuration file in the config.proto ProtoBuf format (see configs/ directory for examples)
 --exec_file|-x VALUE
	File to exec (default: argv[0])
 --execute_fd 
	Use execveat() to execute a file-descriptor instead of executing the binary path. In such case argv[0]/exec_file denotes a file path before mount namespacing
 --chroot|-c VALUE
	Directory containing / of the jail (default: none)
 --rw 
	Mount chroot dir (/) R/W (default: R/O)
 --user|-u VALUE
	Username/uid of processess inside the jail (default: your current uid). You can also use inside_ns_uid:outside_ns_uid:count convention here. Can be specified multiple times
 --group|-g VALUE
	Groupname/gid of processess inside the jail (default: your current gid). You can also use inside_ns_gid:global_ns_gid:count convention here. Can be specified multiple times
 --hostname|-H VALUE
	UTS name (hostname) of the jail (default: 'NSJAIL')
 --cwd|-D VALUE
	Directory in the namespace the process will run (default: '/')
 --port|-p VALUE
	TCP port to bind to (enables MODE_LISTEN_TCP) (default: 0)
 --bindhost VALUE
	IP address to bind the port to (only in [MODE_LISTEN_TCP]), (default: '::')
 --max_conns_per_ip|-i VALUE
	Maximum number of connections per one IP (only in [MODE_LISTEN_TCP]), (default: 0 (unlimited))
 --log|-l VALUE
	Log file (default: use log_fd)
 --log_fd|-L VALUE
	Log FD (default: 2)
 --time_limit|-t VALUE
	Maximum time that a jail can exist, in seconds (default: 600)
 --max_cpus VALUE
	Maximum number of CPUs a single jailed process can use (default: 0 'no limit')
 --daemon|-d 
	Daemonize after start
 --verbose|-v 
	Verbose output
 --quiet|-q 
	Log warning and more important messages only
 --really_quiet|-Q 
	Log fatal messages only
 --keep_env|-e 
	Pass all environment variables to the child process (default: all envvars are cleared)
 --env|-E VALUE
	Additional environment variable (can be used multiple times)
 --keep_caps 
	Don't drop any capabilities
 --cap VALUE
	Retain this capability, e.g. CAP_PTRACE (can be specified multiple times)
 --silent 
	Redirect child process' fd:0/1/2 to /dev/null
 --stderr_to_null
	Redirect FD=2 (STDERR_FILENO) to /dev/null
 --skip_setsid 
	Don't call setsid(), allows for terminal signal handling in the sandboxed process. Dangerous
 --pass_fd VALUE
	Don't close this FD before executing the child process (can be specified multiple times), by default: 0/1/2 are kept open
 --disable_no_new_privs 
	Don't set the prctl(NO_NEW_PRIVS, 1) (DANGEROUS)
 --rlimit_as VALUE
	RLIMIT_AS in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 512)
 --rlimit_core VALUE
	RLIMIT_CORE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 0)
 --rlimit_cpu VALUE
	RLIMIT_CPU, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 600)
 --rlimit_fsize VALUE
	RLIMIT_FSIZE in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 1)
 --rlimit_nofile VALUE
	RLIMIT_NOFILE, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 32)
 --rlimit_nproc VALUE
	RLIMIT_NPROC, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')
 --rlimit_stack VALUE
	RLIMIT_STACK in MB, 'max' or 'hard' for the current hard limit, 'def' or 'soft' for the current soft limit, 'inf' for RLIM64_INFINITY (default: 'soft')
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
	Don't use CLONE_NEWNET. Enable global networking inside the jail
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
 --disable_clone_newcgroup 
	Don't use CLONE_NEWCGROUP. Might be required for kernel versions < 4.6
 --uid_mapping|-U VALUE
	Add a custom uid mapping of the form inside_uid:outside_uid:count. Setting this requires newuidmap (set-uid) to be present
 --gid_mapping|-G VALUE
	Add a custom gid mapping of the form inside_gid:outside_gid:count. Setting this requires newgidmap (set-uid) to be present
 --bindmount_ro|-R VALUE
	List of mountpoints to be mounted --bind (ro) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'
 --bindmount|-B VALUE
	List of mountpoints to be mounted --bind (rw) inside the container. Can be specified multiple times. Supports 'source' syntax, or 'source:dest'
 --tmpfsmount|-T VALUE
	List of mountpoints to be mounted as tmpfs (R/W) inside the container. Can be specified multiple times. Supports 'dest' syntax. Alternatively, use '-m none:dest:tmpfs:size=8388608'
 --mount|-m VALUE
	Arbitrary mount, format src:dst:fs_type:options
 --symlink|-s VALUE
	Symlink, format src:dst
 --disable_proc 
	Disable mounting procfs in the jail
 --proc_path VALUE
	Path used to mount procfs (default: '/proc')
 --proc_rw 
	Is procfs mounted as R/W (default: R/O)
 --seccomp_policy|-P VALUE
	Path to file containing seccomp-bpf policy (see kafel/)
 --seccomp_string VALUE
	String with kafel seccomp-bpf policy (see kafel/)
 --seccomp_log 
	Use SECCOMP_FILTER_FLAG_LOG. Log all actions except SECCOMP_RET_ALLOW). Supported since kernel version 4.14
 --cgroup_mem_max VALUE
	Maximum number of bytes to use in the group (default: '0' - disabled)
 --cgroup_mem_mount VALUE
	Location of memory cgroup FS (default: '/sys/fs/cgroup/memory')
 --cgroup_mem_parent VALUE
	Which pre-existing memory cgroup to use as a parent (default: 'NSJAIL')
 --cgroup_pids_max VALUE
	Maximum number of pids in a cgroup (default: '0' - disabled)
 --cgroup_pids_mount VALUE
	Location of pids cgroup FS (default: '/sys/fs/cgroup/pids')
 --cgroup_pids_parent VALUE
	Which pre-existing pids cgroup to use as a parent (default: 'NSJAIL')
 --cgroup_net_cls_classid VALUE
	Class identifier of network packets in the group (default: '0' - disabled)
 --cgroup_net_cls_mount VALUE
	Location of net_cls cgroup FS (default: '/sys/fs/cgroup/net_cls')
 --cgroup_net_cls_parent VALUE
	Which pre-existing net_cls cgroup to use as a parent (default: 'NSJAIL')
 --cgroup_cpu_ms_per_sec VALUE
	Number of milliseconds of CPU time per second that the process group can use (default: '0' - no limit)
 --cgroup_cpu_mount VALUE
	Location of cpu cgroup FS (default: '/sys/fs/cgroup/net_cls')
 --cgroup_cpu_parent VALUE
	Which pre-existing cpu cgroup to use as a parent (default: 'NSJAIL')
 --iface_no_lo 
	Don't bring the 'lo' interface up
 --iface_own VALUE
	Move this existing network interface into the new NET namespace. Can be specified multiple times
 --macvlan_iface|-I VALUE
	Interface which will be cloned (MACVLAN) and put inside the subprocess' namespace as 'vs'
 --macvlan_vs_ip VALUE
	IP of the 'vs' interface (e.g. "192.168.0.1")
 --macvlan_vs_nm VALUE
	Netmask of the 'vs' interface (e.g. "255.255.255.0")
 --macvlan_vs_gw VALUE
	Default GW for the 'vs' interface (e.g. "192.168.0.1")
 --macvlan_vs_ma VALUE
	MAC-address of the 'vs' interface (e.g. "ba:ad:ba:be:45:00")

 Examples: 
 Wait on a port 31337 for connections, and run /bin/sh
  nsjail -Ml --port 31337 --chroot / -- /bin/sh -i
 Re-run echo command as a sub-process
  nsjail -Mr --chroot / -- /bin/echo "ABC"
 Run echo command once only, as a sub-process
  nsjail -Mo --chroot / -- /bin/echo "ABC"
 Execute echo command directly, without a supervising process
  nsjail -Me --chroot / --disable_proc -- /bin/echo "ABC"
</pre>

***
### Launching in Docker

To launch nsjail in a docker container clone the repository and build the docker image:
<pre>
docker build -t nsjailcontainer .
</pre>

This will build up an image containing njsail and kafel.

From now you can either use it in another Dockerfile (`FROM nsjailcontainer`) or directly:
<pre>
docker run --privileged --rm -it nsjailcontainer nsjail --user 99999 --group 99999 --disable_proc --chroot / --time_limit 30 /bin/bash
</pre>

***
### Contact

  * User mailing list: [nsjail@googlegroups.com](mailto:nsjail@googlegroups.com), sign up with this [link](https://groups.google.com/forum/#!forum/nsjail)
