from DatabaseClasses import *
from proxmox_api_calls import *
import subprocess
import os
import time
from tenacity import retry, stop_after_attempt, wait_fixed

DNSMASQ_INSTANCES_DIR = "/etc/dnsmasq-instances"


def stop_challenge(user_id, db_conn):
    """
    Stop a challenge for a user.
    """

    with db_conn:
        challenge, user_vpn_ip = fetch_challenge(user_id, db_conn)

        fetch_machines(challenge, db_conn)

        stop_machines(challenge)

        delete_machines(challenge)

        fetch_networks(challenge, db_conn)

        delete_network_devices(challenge)

        delete_iptables_rules(challenge, user_vpn_ip)

        stop_dnsmasq_instances(challenge)

        remove_database_entries(challenge, user_id, db_conn)


def fetch_challenge(user_id, db_conn):
    """
    Fetch the challenge for a user.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT running_challenge, vpn_static_ip FROM users WHERE id = %s", (user_id,))

        challenge_id, vpn_static_ip = cursor.fetchone()

    if challenge_id is None:
        raise Exception("No challenge found for user.")

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, challenge_template_id, subnet FROM challenges WHERE id = %s", (challenge_id,))

        challenge_id, template_id, subnet = cursor.fetchone()

    challenge_template = ChallengeTemplate(template_id)
    challenge_subnet = ChallengeSubnet(subnet)
    challenge = Challenge(challenge_id, challenge_template, challenge_subnet.subnet)

    return challenge, vpn_static_ip


def fetch_machines(challenge, db_conn):
    """
    Fetch the machines for a challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id, machine_template_id FROM machines WHERE challenge_id = %s", (challenge.id,))

        for machine_id, template_id in cursor.fetchall():
            machine_template = MachineTemplate(machine_id, challenge.template)

            machine = Machine(machine_id, machine_template, challenge)

            challenge.add_machine(machine)


def fetch_networks(challenge, db_conn):
    """
    Fetch the networks for a challenge.
    """

    for machine in challenge.machines.values():
        with db_conn.cursor() as cursor1:
            cursor1.execute("""
                SELECT n.id, n.network_template_id, n.subnet, n.host_device, c.client_ip, c.client_mac
                FROM networks n, network_connections c
                WHERE c.network_id = n.id
                AND c.machine_id = %s
            """, (machine.id,))

            for network_id, template_id, subnet, host_device, client_ip, client_mac in cursor1.fetchall():
                if network_id not in challenge.networks:
                    with db_conn.cursor() as cursor2:
                        cursor2.execute("SELECT accessible, is_dmz "
                                        "FROM network_templates "
                                        "WHERE id = %s", (template_id,))
                        accessible, is_dmz = cursor2.fetchone()

                    network_template = NetworkTemplate(template_id, accessible)
                    network = Network(network_id, network_template, subnet, host_device, accessible)
                    network.set_is_dmz(is_dmz)

                    challenge.add_network(network)

                connection = Connection(machine, challenge.networks[network_id], client_mac, client_ip)
                challenge.networks[network_id].add_connection(connection)


@retry(stop=stop_after_attempt(5), wait=wait_fixed(1))
def stop_machines(challenge):
    """
    Stop the machines for a challenge.
    """
    existing_machines = {}

    # Remove nonexistent machines
    for machine in challenge.machines.values():
        if vm_exists_api_call(machine):
            existing_machines[machine.id] = machine

    for machine in existing_machines.values():
        stop_vm_api_call(machine)

    all_machines_stopped = True
    for machine in existing_machines.values():
        try:
            if not vm_is_stopped_api_call(machine):
                all_machines_stopped = False
        except Exception:
            all_machines_stopped = False

    if not all_machines_stopped:
        raise Exception(f"Not all machines could be stopped, running machines: {', '.join(str(m.id) for m in existing_machines.values() if not vm_is_stopped_api_call(m))}.")


@retry(stop=stop_after_attempt(5), wait=wait_fixed(1))
def delete_machines(challenge):
    """
    Delete the machines for a challenge.
    """

    existing_machines = {}

    # Remove nonexistent machines
    for machine in challenge.machines.values():
        if vm_exists_api_call(machine):
            existing_machines[machine.id] = machine

    for machine in existing_machines.values():
        try:
            delete_vm_api_call(machine)
        except Exception:
            pass

    all_machines_deleted = True
    for machine in existing_machines.values():
        try:
            if vm_exists_api_call(machine):
                all_machines_deleted = False
                break
        except Exception:
            all_machines_deleted = False

    if not all_machines_deleted:
        raise Exception(f"Not all machines could be deleted. Running machines: {', '.join(str(m.id) for m in existing_machines.values() if vm_exists_api_call(m))}.")


def delete_network_devices(challenge):
    """
    Delete the networks for a challenge.
    """

    for network in challenge.networks.values():
        try:
            delete_network_api_call(network)
        except Exception:
            pass

    reload_network_api_call()


def wait_for_network_devices_deletion(challenge, try_timeout=3, max_tries=10):
    """
    Wait for the networks for a challenge to be deleted.
    """

    all_networks_deleted = False
    tries = 0
    while not all_networks_deleted and tries < max_tries:
        tries += 1
        try_start = time.time()

        while not time.time() - try_start < try_timeout:
            all_networks_deleted = True
            for network in challenge.networks.values():
                if os.path.exists(f"/sys/class/net/{network.host_device}"):
                    all_networks_deleted = False
                    break

        reload_network_api_call()

    if not all_networks_deleted:
        raise Exception(f"Not all network devices could be deleted. Existing devices: {', '.join(str(n.host_device) for n in challenge.networks.values() if network_device_exists_api_call(n))}.")


def delete_iptables_rules(challenge, user_vpn_ip):
    """
    Remove iptables rules previously added for the given user VPN IP.
    """

    for network in challenge.networks.values():
        if network.is_dmz:
            # Allow traffic from the DMZ to the outside
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-i", "vmbr0", "-o", network.host_device, "-d", network.subnet, "-m",
                 "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True)
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-i", network.host_device, "-o", "vmbr0", "-s", network.subnet, "-m",
                 "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True)
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", network.subnet, "-o", "vmbr0", "-j", "MASQUERADE"],
                capture_output=True)

        if network.accessible:
            # Disallow traffic to the router IP
            subprocess.run(["iptables", "-D", "INPUT", "-i", "tun0", "-d", network.router_ip, "-j", "DROP"],
                           capture_output=True)
            for network_connection in network.connections.values():
                # Allow traffic from the user VPN IP to the client IP
                subprocess.run(
                    ["iptables", "-D", "FORWARD", "-i", network.host_device, "-o", "tun0", "-d", user_vpn_ip, "-s",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], capture_output=True)
                subprocess.run(
                    ["iptables", "-D", "FORWARD", "-i", "tun0", "-o", network.host_device, "-s", user_vpn_ip, "-d",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], capture_output=True)

        # Disallow traffic to the router IP
        subprocess.run(["iptables", "-D", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-j", "DROP"],
                       capture_output=True)
        subprocess.run(
            ["iptables", "-D", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "tcp", "--dport",
             "53", "-j", "ACCEPT"], capture_output=True)

        # Allow DNS traffic to the router IP
        subprocess.run(
            ["iptables", "-D", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "udp", "--dport",
             "53", "-j", "ACCEPT"], capture_output=True)

        # Allow intra-network traffic
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-i", network.host_device, "-o", network.host_device, "-j", "ACCEPT"],
            capture_output=True)


def stop_dnsmasq_instances(challenge):
    """
    Delete the dnsmasq configs for a challenge.
    """

    for network in challenge.networks.values():
        config_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.conf")
        pid_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.pid")
        leases_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.leases")
        log_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.log")

        if os.path.exists(config_path):
            os.remove(config_path)

        if os.path.exists(pid_path):
            with open(pid_path, "r") as f:
                try:
                    pid = int(f.read().strip())
                except ValueError:
                    continue
            try:
                os.kill(pid, 9)

            except ProcessLookupError:
                pass

            os.remove(pid_path)

        if os.path.exists(leases_path):
            os.remove(leases_path)

        if os.path.exists(log_path):
            os.remove(log_path)


def remove_database_entries(challenge, user_id, db_conn):
    """
    Remove the database entries for a challenge.
    """

    with db_conn.cursor() as cursor:
        for machine in challenge.machines.values():
            cursor.execute("DELETE FROM domains WHERE machine_id = %s", (machine.id,))
            cursor.execute("DELETE FROM network_connections WHERE machine_id = %s", (machine.id,))
            cursor.execute("DELETE FROM machines WHERE id = %s", (machine.id,))

        for network in challenge.networks.values():
            cursor.execute("DELETE FROM networks WHERE id = %s", (network.id,))

        cursor.execute("UPDATE users SET running_challenge = NULL WHERE id = %s", (user_id,))

        cursor.execute("DELETE FROM challenges WHERE id = %s", (challenge.id,))

        cursor.execute("UPDATE challenge_subnets SET available = TRUE WHERE subnet = %s", (challenge.subnet,))
