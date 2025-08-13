import os
import shlex
import subprocess
import tempfile
import time
import json
from typing import Optional, Tuple, Dict, Any

class NetnsPacketDryRun:
    """
    Creates a temporary namespace with cloned firewall/routing setup,
    uses iptables TRACE to follow packet path and determine if it would be forwarded.
    """

    def __init__(self, name: str = "testns_dryrun", dry_run: bool = False):
        self.name = name
        self.dry_run = dry_run
        self._tmpdir = tempfile.mkdtemp(prefix=f"ns_test_{name}_")
        self._created = False

        if os.geteuid() != 0 and not dry_run:
            raise PermissionError("This script must be run as root")

        try:
            self._run(f"ip netns add {shlex.quote(self.name)}")
            self._run_netns("ip link set lo up")
            self._clone_firewall_and_routes()
            self._created = True
        except Exception:
            self.close()
            raise

    # -------------------- helpers --------------------
    def _run(self, cmd: str, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command on the host."""
        if self.dry_run:
            print(f"[dry-run host] {cmd}")
            return subprocess.CompletedProcess(args=cmd, returncode=0)
        return subprocess.run(cmd, shell=True, check=check, text=True,
                              stdout=(subprocess.PIPE if capture_output else None),
                              stderr=(subprocess.PIPE if capture_output else None))

    def _run_netns(self, cmd: str, ns: Optional[str] = None, check: bool = True, capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command inside a network namespace."""
        ns_name = ns or self.name
        full = f"ip netns exec {shlex.quote(ns_name)} {cmd}"
        if self.dry_run:
            print(f"[dry-run {ns_name}] {cmd}")
            return subprocess.CompletedProcess(args=full, returncode=0)
        return subprocess.run(full, shell=True, check=check, text=True,
                              stdout=(subprocess.PIPE if capture_output else None),
                              stderr=(subprocess.PIPE if capture_output else None))

    def _clone_firewall_and_routes(self):
        """Clone host iptables and routing config into our new namespace."""
        # Clone routing table
        routes = self._run("ip route show", capture_output=True).stdout
        for line in routes.splitlines():
            self._run_netns(f"ip route add {shlex.quote(line)}")

        # Clone iptables (filter, nat, mangle, raw)
        for table in ["filter", "nat", "mangle", "raw"]:
            rules = self._run(f"iptables-save -t {table}", capture_output=True).stdout
            if rules.strip():
                self._run_netns(f"iptables-restore", capture_output=False, check=True).stdin = rules

    def _enable_trace_rule(self, proto: str, sport: int, dport: int):
        """Insert iptables TRACE rule for matching packets."""
        self._run_netns(
            f"iptables -t raw -A PREROUTING -p {proto} "
            f"--sport {sport} --dport {dport} -j TRACE"
        )

    def _clear_trace_rule(self):
        self._run_netns("iptables -t raw -F PREROUTING")

    # -------------------- core logic --------------------
    def send_packet_and_get_verdict(self, packet: dict, count: int = 1, timeout: int = 3) -> Tuple[Dict[str, Any], str]:
        src = packet.get("src")
        dst = packet.get("dst")
        proto = packet.get("proto", "tcp").lower()
        sport = packet.get("sport", 8000)
        dport = packet.get("dport", 8000)

        self._enable_trace_rule(proto, sport, dport)

        # Clear dmesg before sending packet
        self._run_netns("dmesg -C")

        # Send packet using nping (or hping3)
        self._run_netns(
            f"nping --{proto} -c {count} -p {dport} --source-port {sport} {dst}",
            check=False
        )

        time.sleep(0.5)  # wait for logs

        logs = self._run_netns("dmesg", capture_output=True).stdout
        self._clear_trace_rule()

        verdict = "UNKNOWN"
        if "ACCEPT" in logs:
            verdict = "FORWARDED"
        elif "DROP" in logs:
            verdict = "DROPPED"

        verdict_info = {
            "src_ip": src,
            "dst_ip": dst,
            "proto": proto,
            "src_port": sport,
            "dst_port": dport,
            "trace_logs": logs,
            "forwarded": (verdict == "FORWARDED")
        }

        return {"verdict": verdict, "details": verdict_info}, json.dumps(verdict_info, indent=2)

    # -------------------- cleanup --------------------
    def close(self):
        if self.dry_run:
            print("dry_run mode - not cleaning up")
            return
        if self._created:
            try:
                self._run(f"ip netns delete {shlex.quote(self.name)}")
            except Exception as e:
                print("Warning: failed to delete namespace:", e)
            self._created = False
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
        self.close()
