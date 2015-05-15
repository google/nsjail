### WHAT IS IT?
NsJail is a Linux process isolation tool making use of the namespacing features, and seccomp-bpf filters of the Linux kernel

This is NOT an official Google product.

### WHAT KIND OF ISOLATION DOES IT PROVIDE?
1. Linux namespaces: UTS, MOUNT, PID, IPC, NET, USER (optional)
2. FS chroot-ing (chroot()/pivot_root())
3. Seccomp-bpf syscall filters

### WHAT USE-CASES DOES IT COVER?
1. Isolating networking daemons (inetd-style)


+ Server:
 $ ./nsjail -Ml --port 9000 --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i

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
```

2. Isolating local processes (run it once, and exit)
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
 / $exit
 $
```

3. Isolating local processes (and re-running them)
```
 $ ./nsjail -Mr --chroot /chroot/ --user 99999 --group 99999 -- /bin/sh -i
 BusyBox v1.21.1 (Ubuntu 1:1.21.0-1ubuntu1) built-in shell (ash)
 Enter 'help' for a list of built-in commands.
 / $ exit
 BusyBox v1.21.1 (Ubuntu 1:1.21.0-1ubuntu1) built-in shell (ash)
 Enter 'help' for a list of built-in commands.
 / $
```

### MORE INFO?
Type: './nsjail --help' - cmd-line switches are well-documented
