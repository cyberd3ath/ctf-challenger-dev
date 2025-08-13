import sys
BACKEND_FILES_DIR = "/root/ctf-challenger/backend"
sys.path.append(BACKEND_FILES_DIR)
from subnet_calculations import nth_machine_ip

def generate_test_packets(challenge, user_vpn_ip):
    """
    Generate a dictionary of test packets for network traffic validation.
    """

    test_packets = {}

    for network in challenge.networks.values():
        existing_ips = [conn.client_ip for conn in network.connections.values()]

        # ---- 1. Intra-network ----
        if len(existing_ips) >= 2:
            # Allowed: between two real machines in same network
            test_packets[{
                "src": existing_ips[0],
                "dst": existing_ips[1],
                "sport": 12345,
                "dport": 80,
            }] = True

        # ---- 2. DNS to router ----
        for proto in ("udp", "tcp"):
            test_packets[{
                "src": existing_ips[0],
                "dst": network.router_ip,
                "sport": 12345,
                "dport": 53,
                "proto": proto
            }] = True

        # ---- 3. Non-DNS to router (should be blocked) ----
        test_packets[{
            "src": existing_ips[0],
            "dst": network.router_ip,
            "sport": 12345,
            "dport": 80,
        }] = False

        # ---- 4. Cross-network breakout attempt ----
        for other_net in challenge.networks.values():
            if other_net.id != network.id:
                # From a real machine in this net → a real machine in another net
                if other_net.connections:
                    test_packets[{
                        "src": existing_ips[0],
                        "dst": list(other_net.connections.values())[0].client_ip,
                        "sport": 12345,
                        "dport": 80,
                    }] = False

        # ---- 5. Non-existent IP in same subnet (should be blocked) ----
        fake_ip = nth_machine_ip(network.subnet, 14)  # pick one that's not in connections
        if fake_ip not in existing_ips:
            test_packets[{
                "src": existing_ips[0],
                "dst": fake_ip,
                "sport": 12345,
                "dport": 80,
            }] = False

        # ---- 6. VPN rules ----
        if network.accessible:
            for conn in network.connections.values():
                # VPN → existing client allowed
                test_packets[{
                    "src": user_vpn_ip,
                    "dst": conn.client_ip,
                    "sport": 40000,
                    "dport": 22,
                }] = True

                # Client → VPN allowed
                test_packets[{
                    "src": conn.client_ip,
                    "dst": user_vpn_ip,
                    "sport": 22,
                    "dport": 40000,
                }] = True

            # VPN → router blocked (except DNS)
            test_packets[{
                "src": user_vpn_ip,
                "dst": network.router_ip,
                "sport": 40000,
                "dport": 80,
            }] = False
            test_packets[{
                "src": user_vpn_ip,
                "dst": network.router_ip,
                "sport": 40000,
                "dport": 53,
                "proto": "udp"
            }] = True
        else:
            # VPN → inaccessible network blocked
            test_packets[{
                "src": user_vpn_ip,
                "dst": existing_ips[0],
                "sport": 40000,
                "dport": 80,
            }] = False

        # ---- 7. Internet access ----
        if network.is_dmz:
            # DMZ → outside allowed
            test_packets[{
                "src": existing_ips[0],
                "dst": "8.8.8.8",
                "sport": 12345,
                "dport": 80,
            }] = True
            # Outside → DMZ new blocked
            test_packets[{
                "src": "8.8.8.8",
                "dst": existing_ips[0],
                "sport": 80,
                "dport": 12345,
            }] = False
            # Outside → DMZ established allowed
            test_packets[{
                "src": "8.8.8.8",
                "dst": existing_ips[0],
                "sport": 80,
                "dport": 12345,
                "state": "ESTABLISHED"
            }] = True
        else:
            # Non-DMZ → outside blocked
            test_packets[{
                "src": existing_ips[0],
                "dst": "8.8.8.8",
                "sport": 12345,
                "dport": 80,
            }] = False

    # ---- 8. VPN breakout attempt → internet (should be blocked) ----
    test_packets[{
        "src": user_vpn_ip,
        "dst": "8.8.8.8",
        "sport": 50000,
        "dport": 80,
    }] = False

