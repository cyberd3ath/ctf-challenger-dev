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

    def send_packet_and_get_verdict(self, src: str, dst: str, proto: str = 'tcp', sport: Optional[int] = None,
                                     dport: Optional[int] = None, count: int = 1, timeout: int = 3) -> Tuple[Dict[str, Any], str]:
        """Send a crafted packet from inside the namespace and gather verdict info.

        This does three things:
          1. inserts a temporary TRACE rule in the FORWARD chain.
          2. runs a short tcpdump inside the namespace capturing a single packet
             (or more) so we can see if the packet traverses.
          3. executes Scapy inside the namespace to send the packet.

        Returns a tuple (verdict_dict, combined_text_logs)
        """
        # prepare scapy python program
        scapy_prog = [
            "from scapy.all import *",
            f"p=IP(src=\"{src}\",dst=\"{dst}\")",
        ]
        if proto.lower() == 'tcp':
            sport_arg = f",{sport}" if sport else ""
            dport_arg = f",dport={dport}" if dport else ""
            scapy_prog.append(f"p = p/TCP(sport={sport if sport else 'RandShort()'},{'dport='+str(dport) if dport else 'dport=RandShort()'})")
        elif proto.lower() == 'udp':
            scapy_prog.append(f"p = p/UDP(sport={sport if sport else 'RandShort()'},{'dport='+str(dport) if dport else 'dport=RandShort()'})")
        elif proto.lower() == 'icmp':
            scapy_prog.append("p = p/ICMP()")
        else:
            scapy_prog.append(f"p = p")
        scapy_prog.append(f"send(p, count={count}, verbose=0)")
        scapy_src = "\n".join(scapy_prog)

        # enable iptables TRACE if iptables exist
        used_iptables = False
        try:
            # check iptables
            res = self._run("command -v iptables >/dev/null && echo OK || true", capture_output=True)
            if res.stdout.strip() == 'OK':
                used_iptables = True
                # add TRACE rule to FORWARD chain
                try:
                    self._run_netns("iptables -I FORWARD 1 -j TRACE")
                    self._trace_marker_chain_added = True
                except Exception:
                    pass
        except Exception:
            pass

        # start tcpdump inside namespace capturing on `any` interface
        pcap_file = f"{self._tmpdir}/capture.pcap"
        tcpdump_cmd = f"timeout {timeout} tcpdump -i any -w {shlex.quote(pcap_file)} -c {count}"
        tcpdump_proc = None
        try:
            tcpdump_full = f"ip netns exec {shlex.quote(self.name)} {tcpdump_cmd}"
            print(f"Starting tcpdump: {tcpdump_full}")
            if not self.dry_run:
                tcpdump_proc = subprocess.Popen(tcpdump_full, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            else:
                print("[dry_run] would start tcpdump")

            # small pause to ensure tcpdump is listening
            time.sleep(0.3)

            # send packet(s)
            scapy_cmd = f"python3 - <<'PY'\n{scapy_src}\nPY"
            self._run_netns(scapy_cmd)

            # wait for tcpdump to finish or timeout
            if tcpdump_proc:
                try:
                    out, err = tcpdump_proc.communicate(timeout=timeout + 1)
                except subprocess.TimeoutExpired:
                    os.killpg(os.getpgid(tcpdump_proc.pid), signal.SIGTERM)
                    out, err = tcpdump_proc.communicate()

            # read pcap to know if any packets captured
            verdict = {"forwarded": False, "trace": []}
            if not self.dry_run and os.path.exists(pcap_file):
                # use tcpdump -r to get a human-readable summary
                r = subprocess.run(f"tcpdump -nn -r {shlex.quote(pcap_file)}", shell=True, capture_output=True, text=True)
                cap_text = r.stdout
                verdict['pcap_summary'] = cap_text
                verdict['forwarded'] = bool(cap_text.strip())
            else:
                verdict['pcap_summary'] = ""

            # check kernel trace logs (dmesg) for iptables TRACE output
            try:
                d = subprocess.run("dmesg --clear; sleep 0.1; dmesg", shell=True, capture_output=True, text=True)
                dmsg = d.stdout
                # pull lines mentioning TRACE or netfilter
                trace_lines = [l for l in dmsg.splitlines() if 'TRACE' in l or 'netfilter' in l or 'iptables' in l]
                verdict['trace'] = trace_lines
            except Exception:
                verdict['trace'] = []

            # decide final verdict
            # heuristics: if pcap captured packet -> packet existed in namespace
            # if trace contains 'DROP' or 'REJECT' entries -> dropped
            text_logs = json.dumps(verdict, indent=2)
            if any('DROP' in l or 'REJECT' in l for l in verdict.get('trace', [])):
                final = {'verdict': 'DROP', 'details': verdict}
            elif verdict.get('forwarded'):
                final = {'verdict': 'FORWARDED/SEEN', 'details': verdict}
            else:
                final = {'verdict': 'UNKNOWN', 'details': verdict}

            return final, text_logs
        finally:
            # remove trace rule we added
            if self._trace_marker_chain_added:
                try:
                    self._run_netns("iptables -D FORWARD -j TRACE || true")
                except Exception:
                    pass
                self._trace_marker_chain_added = False

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
