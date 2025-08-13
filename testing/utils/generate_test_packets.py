import sys
BACKEND_FILES_DIR = "/root/ctf-challenger/backend"
sys.path.append(BACKEND_FILES_DIR)
from subnet_calculations import nth_machine_ip

def generate_test_packets(challenge, user_vpn_ip):
    """
    Generate a list of test packets for network traffic validation.
    Each element is a dict containing packet fields + an 'allowed' boolean.
    """

    test_packets = []

    for network in challenge.networks.values():
        existing_ips = [conn.client_ip for conn in network.connections.values()]

        # ---- 1. Intra-network ----
        if len(existing_ips) >= 2:
            test_packets.append({
                "src": existing_ips[0],
                "dst": existing_ips[1],
                "sport": 12345,
                "dport": 80,
                "allowed": True
            })

        # ---- 2. DNS to router ----
        for proto in ("udp", "tcp"):
            test_packets.append({
                "src": existing_ips[0],
                "dst": network.router_ip,
                "sport": 12345,
                "dport": 53,
                "proto": proto,
                "allowed": True
            })

        # ---- 3. Non-DNS to router (should be blocked) ----
        test_packets.append({
            "src": existing_ips[0],
            "dst": network.router_ip,
            "sport": 12345,
            "dport": 80,
            "allowed": False
        })

        # ---- 4. Cross-network breakout attempt ----
        for other_net in challenge.networks.values():
            if other_net.id != network.id and other_net.connections:
                test_packets.append({
                    "src": existing_ips[0],
                    "dst": list(other_net.connections.values())[0].client_ip,
                    "sport": 12345,
                    "dport": 80,
                    "allowed": False
                })

        # ---- 5. Non-existent IP in same subnet ----
        fake_ip = nth_machine_ip(network.subnet, 14)
        if fake_ip not in existing_ips:
            test_packets.append({
                "src": existing_ips[0],
                "dst": fake_ip,
                "sport": 12345,
                "dport": 80,
                "allowed": False
            })

        # ---- 6. VPN rules ----
        if network.accessible:
            for conn in network.connections.values():
                # VPN → client allowed
                test_packets.append({
                    "src": user_vpn_ip,
                    "dst": conn.client_ip,
                    "sport": 40000,
                    "dport": 22,
                    "allowed": True
                })
                # Client → VPN allowed
                test_packets.append({
                    "src": conn.client_ip,
                    "dst": user_vpn_ip,
                    "sport": 22,
                    "dport": 40000,
                    "allowed": True
                })

            # VPN → router blocked (except DNS)
            test_packets.append({
                "src": user_vpn_ip,
                "dst": network.router_ip,
                "sport": 40000,
                "dport": 80,
                "allowed": False
            })
            test_packets.append({
                "src": user_vpn_ip,
                "dst": network.router_ip,
                "sport": 40000,
                "dport": 53,
                "proto": "udp",
                "allowed": True
            })
        else:
            # VPN → inaccessible network blocked
            test_packets.append({
                "src": user_vpn_ip,
                "dst": existing_ips[0],
                "sport": 40000,
                "dport": 80,
                "allowed": False
            })

        # ---- 7. Internet access ----
        if network.is_dmz:
            # DMZ → outside allowed
            test_packets.append({
                "src": existing_ips[0],
                "dst": "8.8.8.8",
                "sport": 12345,
                "dport": 80,
                "allowed": True
            })
            # Outside → DMZ new blocked
            test_packets.append({
                "src": "8.8.8.8",
                "dst": existing_ips[0],
                "sport": 80,
                "dport": 12345,
                "allowed": False
            })
            # Outside → DMZ established allowed
            test_packets.append({
                "src": "8.8.8.8",
                "dst": existing_ips[0],
                "sport": 80,
                "dport": 12345,
                "state": "ESTABLISHED",
                "allowed": True
            })
        else:
            # Non-DMZ → outside blocked
            test_packets.append({
                "src": existing_ips[0],
                "dst": "8.8.8.8",
                "sport": 12345,
                "dport": 80,
                "allowed": False
            })

    # ---- 8. VPN breakout attempt → internet (should be blocked) ----
    test_packets.append({
        "src": user_vpn_ip,
        "dst": "8.8.8.8",
        "sport": 50000,
        "dport": 80,
        "allowed": False
    })

    return test_packets
