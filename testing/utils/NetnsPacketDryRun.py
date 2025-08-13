from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import time
import json
import signal
from typing import Optional, Tuple, Dict, Any, List


class NetnsPacketDryRun:
    """Create an isolated network namespace mirroring host networking.

    On construction this creates the namespace, dummy devices that mirror the
    host interface names and addresses, copies routes, rules and firewall
    configuration, and applies a conservative set of
    sysctl settings so the namespace behaves like the host.

    The namespace is fully isolated: nothing we send from inside will escape
    the host network namespace unless you explicitly connect it. This means
    it's safe for automated tests.
    """

    def __init__(self, name: str = "testns_dryrun", dry_run: bool = False):
        """Create and populate the namespace.

        Args:
            name: namespace name
            dry_run: if True, do not actually run system commands; just print
                     what would be done (useful for CI linting / validation).
        """
        self.name = name
        self.dry_run = dry_run
        self._created = False
        self._trace_marker_chain_added = False
        # keep temporary files (iptables-save etc.) to facilitate cleanup
        self._tmpdir = tempfile.mkdtemp(prefix=f"ns_mirror_{name}_")

        if os.geteuid() != 0 and not dry_run:
            raise PermissionError("This script must be run as root")

        try:
            self._run(f"ip netns add {shlex.quote(self.name)}")
            self._created = True

            self._run_netns("ip link set lo up")
            self._mirror_addresses()
            self._mirror_routes_and_rules()
            self._mirror_sysctls()
            self._mirror_firewall()
            self._mirror_ip_forward()

        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    # -------------------- helpers --------------------
    def _run(self, cmd: str, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a local shell command on the host (not in namespace).

        In dry_run mode we only print the command.
        """
        print(f"[host] $ {cmd}")
        if self.dry_run:
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        return subprocess.run(cmd, shell=True, check=check, text=True,
                              stdout=(subprocess.PIPE if capture_output else None),
                              stderr=(subprocess.PIPE if capture_output else None))

    def _run_netns(self, cmd: str, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
        full = f"ip netns exec {shlex.quote(self.name)} {cmd}"
        print(f"[{self.name}] $ {cmd}")
        if self.dry_run:
            return subprocess.CompletedProcess(args=full, returncode=0)
        return subprocess.run(full, shell=True, check=check, text=True,
                              stdout=(subprocess.PIPE if capture_output else None),
                              stderr=(subprocess.PIPE if capture_output else None))

    def _mirror_addresses(self):
        """Create dummy devices inside the namespace and assign addresses identical
        to those on the host (names are preserved inside namespace).
        """
        # get host interfaces and their addresses
        res = self._run("ip -4 -o addr show", capture_output=True)
        out = res.stdout if res.stdout is not None else ""
        v6 = self._run("ip -6 -o addr show", capture_output=True)
        out6 = v6.stdout if v6.stdout is not None else ""

        # each line: <idx>: <ifname> <family> <addr> ...
        addrs = []  # tuples (ifname, addr, family)
        for line in out.splitlines() + out6.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            ifname = parts[1]
            family = 'inet' if parts[2] == 'inet' else 'inet6'
            addr = parts[3]
            # skip loopback
            if ifname == 'lo':
                continue
            addrs.append((ifname, addr, family))

        # create dummy devices inside namespace and assign addresses
        created_devs = set()
        for ifname, addr, family in addrs:
            if ifname in created_devs:
                # multiple addresses on same interface
                cmd = f"ip addr add {addr} dev {shlex.quote(ifname)}"
                self._run_netns(cmd)
                continue
            # create dummy device
            self._run_netns(f"ip link add {shlex.quote(ifname)} type dummy")
            self._run_netns(f"ip link set {shlex.quote(ifname)} up")
            self._run_netns(f"ip addr add {addr} dev {shlex.quote(ifname)}")
            created_devs.add(ifname)

    def _mirror_routes_and_rules(self):
        """Copy `ip route` and `ip rule` entries into the namespace.

        Notes:
        - We'll copy routes from the main table and rules; some routes that
          reference devices not present or complex policy-based routing may
          need manual adjustments. The script makes a best effort.
        """
        # copy ip rules
        try:
            res = self._run("ip rule show", capture_output=True)
            rules = res.stdout if res.stdout is not None else ""
            for line in rules.splitlines():
                if not line.strip():
                    continue
                # `ip rule add <line>` is not safe because lines include '0:' index.
                # We'll append using `ip rule add` rewriting the common forms.
                # Simpler: write them to a temp file and execute in namespace via shell.
                pass
            # simpler approach: export then import using `ip netns exec ... sh -c` loop
            self._run("ip rule show > {tmp}/iprule_host.txt".format(tmp=self._tmpdir))
            self._run_netns(f"sh -c 'while read line; do ip rule add $line 2>/dev/null || true; done' < {shlex.quote(self._tmpdir)}/iprule_host.txt")
        except Exception:
            # non-fatal
            pass

        # copy routes (IPv4 + IPv6)
        for cmd in ("ip -4 route show", "ip -6 route show"):
            try:
                res = self._run(cmd, capture_output=True)
                routes = res.stdout if res.stdout is not None else ""
                # write to temp file and add inside namespace line-by-line
                with open(f"{self._tmpdir}/routes.txt", "w") as f:
                    f.write(routes)
                # add routes inside namespace (ignore errors)
                self._run_netns(f"sh -c 'while read line; do ip route add $line 2>/dev/null || true; done' < {shlex.quote(self._tmpdir)}/routes.txt")
            except Exception:
                pass

    def _mirror_sysctls(self):
        """Copy a set of sysctl values relevant to forwarding and netfilter.
        """
        keys = [
            'net.ipv4.ip_forward',
            'net.ipv6.conf.all.forwarding',
            'net.netfilter.nf_log_all_netns',
            'net.netfilter.nf_log_all',
        ]
        for k in keys:
            try:
                res = self._run(f"sysctl -n {shlex.quote(k)}", capture_output=True)
                val = res.stdout.strip() if res.stdout else '0'
                self._run_netns(f"sysctl -w {shlex.quote(k)}={shlex.quote(val)}")
            except Exception:
                # ignore missing keys
                pass

    def _mirror_firewall(self):
        """Copy iptables state into the namespace.
        """
        try:
            ipt_save = self._run("command -v iptables-save >/dev/null && iptables-save || true", capture_output=True)
            ipt_output = ipt_save.stdout if ipt_save.stdout is not None else ""
            if ipt_output.strip():
                with open(f"{self._tmpdir}/iptables_rules.v4", "w") as f:
                    f.write(ipt_output)
                self._run_netns(f"iptables-restore < {shlex.quote(self._tmpdir)}/iptables_rules.v4 || true")
            # try ip6tables too
            ip6 = self._run("command -v ip6tables-save >/dev/null && ip6tables-save || true", capture_output=True)
            ip6_output = ip6.stdout if ip6.stdout is not None else ""
            if ip6_output.strip():
                with open(f"{self._tmpdir}/iptables_rules.v6", "w") as f:
                    f.write(ip6_output)
                self._run_netns(f"ip6tables-restore < {shlex.quote(self._tmpdir)}/iptables_rules.v6 || true")
        except Exception:
            pass

    def _mirror_ip_forward(self):
        try:
            res = self._run("cat /proc/sys/net/ipv4/ip_forward", capture_output=True)
            v4 = res.stdout.strip() if res.stdout else "0"
            self._run_netns(f"sysctl -w net.ipv4.ip_forward={shlex.quote(v4)}")
        except Exception:
            pass

    import subprocess
    import time
    import json
    import os
    from typing import Dict, Any, Tuple

    def send_packet_and_get_verdict(self, packet: dict, count: int = 1, timeout: int = 3) -> Tuple[Dict[str, Any], str]:
        """
        Send a crafted packet between two namespaces using dedicated sender/receiver scripts.

        Returns:
            (verdict_dict, logs_as_json_string)
        """

        src = packet.get("src")
        dst = packet.get("dst")
        proto = packet.get("proto", "tcp").lower()
        sport = packet.get("sport", 8000)
        dport = packet.get("dport", 8000)

        # Determine destination namespace
        dst_ns = self._find_namespace_for_ip(dst)
        if not dst_ns:
            raise RuntimeError(f"Could not determine namespace for destination IP {dst}")

        sender_script = os.path.join(self._scripts_dir, "packet_sender.py")
        receiver_script = os.path.join(self._scripts_dir, "packet_receiver.py")

        # Start receiver in destination namespace
        recv_args = [
            "ip", "netns", "exec", dst_ns,
            "python3", receiver_script,
            "--listen", dst,
            "--proto", proto,
            "--timeout", str(timeout)
        ]
        if proto in ("tcp", "udp"):
            recv_args.extend(["--port", str(dport)])

        recv_proc = subprocess.Popen(
            recv_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Give the receiver a moment to bind
        time.sleep(0.5)

        # Run sender in source namespace
        send_args = [
            "ip", "netns", "exec", self.name,
            "python3", sender_script,
            "--src", src,
            "--dst", dst,
            "--proto", proto
        ]
        if proto in ("tcp", "udp"):
            send_args.extend(["--port", str(dport)])

        send_proc = subprocess.Popen(send_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        send_out, send_err = send_proc.communicate(timeout=timeout + 1)

        # Wait for receiver to finish
        try:
            recv_out, recv_err = recv_proc.communicate(timeout=timeout + 1)
        except subprocess.TimeoutExpired:
            recv_proc.kill()
            recv_out, recv_err = recv_proc.communicate()

        # Build verdict
        packet_received = (recv_proc.returncode == 0)
        verdict_info = {
            "src_namespace": self.name,
            "dst_namespace": dst_ns,
            "proto": proto,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport if proto in ("tcp", "udp") else None,
            "dst_port": dport if proto in ("tcp", "udp") else None,
            "receiver_output": recv_out.decode().strip(),
            "receiver_error": recv_err.decode().strip(),
            "sender_output": send_out.decode().strip(),
            "sender_error": send_err.decode().strip(),
            "forwarded": packet_received
        }

        final_verdict = {
            "verdict": "FORWARDED" if packet_received else "DROPPED",
            "details": verdict_info
        }

        return final_verdict, json.dumps(verdict_info, indent=2)

    # -------------------- cleanup --------------------
    def close(self):
        """Tear down the namespace and temporary files.

        Prefer calling this explicitly. `__del__` also calls it as a best-effort.
        """
        if self.dry_run:
            print("dry_run mode - not cleaning up")
            return
        if self._created:
            try:
                print(f"deleting namespace {self.name}")
                self._run(f"ip netns delete {shlex.quote(self.name)}")
            except Exception as e:
                print("warning: failed to delete namespace:", e)
            self._created = False
        # remove tmpdir
        try:
            import shutil
            shutil.rmtree(self._tmpdir)
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
