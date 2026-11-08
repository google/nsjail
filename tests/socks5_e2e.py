#!/usr/bin/env python3
"""Bounded, localhost-only nsjail SOCKS5/UDP integration test.

Run in an ephemeral privileged container with a TUN interface.  A benign
UDP packet from a child in the jail causes its nstun parent to connect to
our in-container fake SOCKS5 server. We intentionally send incomplete
protocol responses and measure only the local supervisor process CPU.
"""
import argparse
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
import pathlib

SCENARIOS = ("greeting_partial", "associate_partial", "associate_ipv6", "established_extra")
MEASURE_SECONDS = 0.9

def read_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        b = sock.recv(n - len(data))
        if not b:
            raise RuntimeError("proxy control channel closed early")
        data.extend(b)
    return bytes(data)

def cpu_seconds(pid):
    # /proc/<pid>/stat: following comm+state, utime/stime are indices 11/12
    value = pathlib.Path("/proc/%d/stat" % pid).read_text()
    fields = value.rsplit(") ", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

def proxy_worker(listener, scenario, handshake_complete, release, outcome):
    try:
        listener.settimeout(8)
        conn, addr = listener.accept()
        with conn:
            conn.settimeout(5)
            assert read_exact(conn, 3) == b"\x05\x01\x00", "bad initial greeting"
            if scenario == "greeting_partial":
                conn.sendall(b"\x05")
            else:
                conn.sendall(b"\x05\x00")
                request = read_exact(conn, 10)
                assert request[:4] == b"\x05\x03\x00\x01", "bad UDP ASSOCIATE request"
                if scenario == "associate_partial":
                    conn.sendall(b"\x05\x00\x00\x01")
                elif scenario == "associate_ipv6":
                    conn.sendall(b"\x05\x00\x00\x04" + b"\0" * 16 + b"\0\0")
                else:
                    conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + b"\xd3\x68")
                    time.sleep(0.08)
                    conn.sendall(b"\x11")
            handshake_complete.set()
            release.wait(5)
    except BaseException as e:
        outcome["error"] = "%s: %s" % (type(e).__name__, e)
        handshake_complete.set()

def scenario_run(executable, label, scenario):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    config = """
name: "socks5-e2e-local"
mode: ONCE
time_limit: 8
clone_newuser: false
clone_newns: false
clone_newpid: false
clone_newipc: false
clone_newuts: false
clone_newcgroup: false
clone_newnet: true
user_net {
  backend: NSTUN
  rule4 {
    direction: GUEST_TO_HOST
    action: ENCAP_SOCKS5
    proto: UDP
    dst_ip: "8.8.8.8/32"
    dport: 53
    redirect_ip: "127.0.0.1"
    redirect_port: %d
  }
}
""" % port
    cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", delete=False)
    cfg_file.write(config)
    cfg_file.close()
    log_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".log", delete=False)
    log_path = log_file.name
    ready = threading.Event()
    release = threading.Event()
    outcome = {}
    thread = threading.Thread(target=proxy_worker,
                              args=(listener, scenario, ready, release, outcome),
                              daemon=True)
    thread.start()
    # Inside the jail, send one benign datagram to trigger a SOCKS5 UDP flow.
    client = ("import socket,time; "
              "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
              "s.sendto(b'e2e-local-test',('8.8.8.8',53)); "
              "time.sleep(3.2)")
    cmd = [executable, "-C", cfg_file.name, "-v",
           "--", "/usr/bin/python3", "-c", client]
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT)
    try:
        if not ready.wait(7):
            raise RuntimeError("proxy was never reached")
        if outcome.get("error"):
            raise RuntimeError("proxy handshake: " + outcome["error"])
        if proc.poll() is not None:
            raise RuntimeError("nsjail exited early: code=%s" % proc.returncode)
        before = cpu_seconds(proc.pid)
        start = time.monotonic()
        time.sleep(MEASURE_SECONDS)
        duration = time.monotonic() - start
        after = cpu_seconds(proc.pid)
        cpu_rate = max(0, after - before) / duration
        print("METRIC version=%s case=%s cpu_seconds=%.4f interval=%.3f cpu_per_core=%.3f" %
              (label, scenario, after - before, duration, cpu_rate), flush=True)
        return cpu_rate
    except BaseException:
        log_file.flush()
        tail = pathlib.Path(log_path).read_text(errors="replace")[-6000:]
        print("FAIL details version=%s scenario=%s\n%s" % (label, scenario, tail), flush=True)
        raise
    finally:
        release.set()
        listener.close()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        thread.join(timeout=1)
        log_file.close()
        pathlib.Path(cfg_file.name).unlink(missing_ok=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", required=True)
    p.add_argument("--patched", required=True)
    p.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
    args = p.parse_args()
    results = {}
    for scenario in args.scenarios:
        if scenario not in SCENARIOS:
            raise ValueError(scenario)
        baseline = scenario_run(args.baseline, "baseline", scenario)
        patched = scenario_run(args.patched, "patched", scenario)
        results[scenario] = (baseline, patched)
    print("\nCOMPARISON", flush=True)
    for scenario, (base, fixed) in results.items():
        print("%s: baseline %.3f / fixed %.3f CPU cores" % (scenario, base, fixed), flush=True)
        if base < 0.25:
            raise AssertionError("baseline did not manifest sustained CPU spinning: " + scenario)
        if fixed > 0.20:
            raise AssertionError("patch still spends substantial CPU: " + scenario)
    print("INTEGRATED_NSTUN_SOCKS5_E2E_PASS", flush=True)

if __name__ == "__main__":
    main()
