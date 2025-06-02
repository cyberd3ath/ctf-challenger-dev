import random
import subprocess
from subnet_calculations import nth_network_subnet
from DatabaseClasses import *
from proxmox_api_calls import *
import os
from stop_challenge import delete_iptables_rules, remove_database_entries, stop_dnsmasq_instances

DNSMASQ_INSTANCES_DIR = "/etc/dnsmasq-instances/"
os.makedirs(DNSMASQ_INSTANCES_DIR, exist_ok=True)


def launch_challenge(challenge_template_id, user_id, db_conn):
    """
    Launch a challenge by creating a user and network device.
    """
    try:
        user_vpn_ip = fetch_user_vpn_ip(user_id, db_conn)

        challenge_template = ChallengeTemplate(challenge_template_id)

        fetch_machines(challenge_template, db_conn)

        fetch_network_and_connection_templates(challenge_template, db_conn)

        fetch_domain_templates(challenge_template, db_conn)

    except Exception as e:
        raise ValueError(f"Error fetching from database: {e}")

    try:
        challenge_subnet = fetch_challenge_subnet(db_conn)

    except Exception as e:
        raise ValueError(f"Error fetching challenge subnet: {e}")

    try:
        challenge = create_challenge(challenge_template, challenge_subnet, db_conn)

    except Exception as e:
        raise ValueError(f"Error creating challenge: {e}")

    try:
        clone_machines(challenge_template, challenge, db_conn)

        create_networks_and_connections(challenge_template, challenge, user_id, db_conn)

        create_domains(challenge_template, challenge, db_conn)

        create_network_devices(challenge)

        wait_for_networks_to_be_up(challenge)

        add_iptables_rules(challenge, user_vpn_ip)

        attach_networks_to_vms(challenge)

        start_dnsmasq_instances(challenge, user_vpn_ip)

        launch_machines(challenge)

        add_running_challenge_to_user(challenge, user_id, db_conn)

    except Exception as e:
        undo_launch_challenge(challenge, user_id, user_vpn_ip, db_conn)
        raise ValueError(f"Error launching challenge: {e}")

    accessible_networks = [network.subnet for network in challenge.networks.values() if network.accessible]
    accessible_networks.sort()

    return accessible_networks


def fetch_machines(challenge_template, db_conn):
    """
    Fetch machine templates for the given challenge.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM machine_templates WHERE challenge_template_id = %s", (challenge_template.id,))

        for row in cursor.fetchall():
            machine_template = MachineTemplate(machine_template_id=row[0], challenge_template=challenge_template)

            # Add machine template to challenge template
            challenge_template.add_machine_template(machine_template)


def fetch_network_and_connection_templates(challenge_template, db_conn):
    """
    Fetch network and connection templates for the given machine templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            SELECT nt.id, nt.accessible, nt.is_dmz
            FROM network_templates nt, network_connection_templates ct
            WHERE ct.machine_template_id = %s
            AND ct.network_template_id = nt.id
            """, (machine_template.id,))

            for row in cursor.fetchall():
                network_id = row[0]

                if challenge_template.network_templates.get(network_id) is None:
                    network_template = NetworkTemplate(network_template_id=network_id, accessible=row[1])
                    network_template.set_is_dmz(row[2])
                    challenge_template.add_network_template(network_template)
                else:
                    network_template = challenge_template.network_templates[network_id]

                connection_template = ConnectionTemplate(
                    machine_template=machine_template,
                    network_template=network_template
                )

                challenge_template.add_connection_template(connection_template)
                network_template.add_connected_machine(machine_template)
                machine_template.add_connected_network(network_template)


def fetch_domain_templates(challenge_template, db_conn):
    """
    Fetch domain templates for the given machine templates and network templates.
    """

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            SELECT dt.domain_name
            FROM domain_templates dt
            WHERE dt.machine_template_id = %s
            """, (machine_template.id,))

            for row in cursor.fetchall():
                domain_template = DomainTemplate(machine_template=machine_template, domain=row[0])

                challenge_template.add_domain_template(domain_template)
                machine_template.add_domain_template(domain_template)


def fetch_challenge_subnet(db_conn):
    """
    Fetch the challenge subnet.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
            UPDATE challenge_subnets
            SET available = FALSE
            WHERE subnet = (
                SELECT subnet
                FROM challenge_subnets
                WHERE available = TRUE
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING subnet
        """)
        result = cursor.fetchone()

        if result is None:
            db_conn.rollback()
            raise ValueError("No available challenge subnet found")

        db_conn.commit()

        challenge_subnet = result[0]
        challenge_subnet = ChallengeSubnet(subnet=challenge_subnet)

        return challenge_subnet


def create_challenge(challenge_template, challenge_subnet, db_conn):
    """
    Create a challenge for the given user ID and challenge template.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("""
        INSERT INTO challenges (id, challenge_template_id, subnet)
        VALUES (
            (
                SELECT COALESCE(MIN(id), 0) + 1 
                FROM challenges c
                WHERE NOT EXISTS(
                    SELECT 1 FROM challenges WHERE id = c.id + 1
                )
                OR c.id = 0                
            ),
            %s, %s
        )
        RETURNING id
        """, (challenge_template.id, challenge_subnet.subnet))

        challenge_id = cursor.fetchone()[0]
        challenge = Challenge(challenge_id=challenge_id, template=challenge_template, subnet=challenge_subnet.subnet)

        db_conn.commit()

    return challenge


def clone_machines(challenge_template, challenge, db_conn):
    """
    Clone machines from the given machine template IDs.
    """

    max_machine_id = 899_999_999

    for machine_template in challenge_template.machine_templates.values():
        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO machines (machine_template_id, challenge_id)
            VALUES (%s, %s)
            RETURNING id
            """, (machine_template.id, challenge.id))

            machine_id = cursor.fetchone()[0]

            if machine_id > max_machine_id:
                db_conn.rollback()
                raise ValueError("Machine ID exceeds maximum limit")

            db_conn.commit()

            machine = Machine(machine_id=machine_id, template=machine_template, challenge=challenge)

            # Add machine template to challenge template
            challenge.add_machine(machine)
            machine_template.set_child(machine)

        clone_vm_api_call(machine_template, machine)


def generate_mac_address(challenge_id, local_network_id, local_connection_id):
    """
    Generate a MAC address based on the machine ID, network ID, and connection ID.
    network_id, connection_id : 1-15 -> 2 nibbles combined
    challenge_id : 100000000 -> 899999999 -> 8 nibbles -> hash to
    """
    challenge_hex = hex(challenge_id)[2:].zfill(8)[-8:]
    challenge_bytes = [challenge_hex[i:i + 2] for i in range(0, len(challenge_hex), 2)]
    network_hex = hex(local_network_id)[2:]
    connection_hex = hex(local_connection_id)[2:]

    if len(challenge_bytes) != 4:
        raise ValueError(f"Challenge ID must be 8 hex digits, got {len(challenge_bytes) * 2} hex digits")

    if len(network_hex) > 1 or len(connection_hex) > 1:
        raise ValueError(f"Network ID and Connection ID must be 1 hex digit, got {len(network_hex)} and "
                         f"{len(connection_hex)} hex digits")

    mac = (f"02:{challenge_bytes[0]}:{challenge_bytes[1]}:{challenge_bytes[2]}:{challenge_bytes[3]}"
           f":{network_hex}{connection_hex}")
    return mac


def create_networks_and_connections(challenge_template, challenge, user_id, db_conn):
    """
    Create networks and connections for the given challenge.
    """

    possible_network_subnets = []

    for i in range(2**4):
        possible_network_subnets.append(nth_network_subnet(challenge.subnet_ip, i))

    network_subnets = random.sample(possible_network_subnets, len(challenge_template.network_templates))

    local_network_id = 0
    for network_template, network_subnet in zip(challenge_template.network_templates.values(), network_subnets):
        local_network_id += 1
        available_client_ips = {nth_machine_ip(network_subnet[:-3], i) for i in range(2, 15)}

        user_id_hex = f"{user_id:06x}"
        local_network_id_hex = f"{local_network_id:01x}"

        network_host_device = f"vrt{user_id_hex}{local_network_id_hex}"

        if len(network_host_device) != 10:
            raise ValueError(f"Network host device must be 10 hex digits, got {len(network_host_device)} hex digits "
                             f"({network_host_device})")

        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO networks (id, network_template_id, subnet, host_device)
            VALUES (
                (
                    SELECT COALESCE(MIN(id), 0) + 1 
                    FROM networks n
                    WHERE NOT EXISTS(
                        SELECT 1 FROM networks WHERE id = n.id + 1
                    )
                    OR n.id = 0                
                ),
                %s, %s, %s
            )
            RETURNING id""", (network_template.id, network_subnet, network_host_device))

            network_id = cursor.fetchone()[0]
            network = Network(
                network_id=network_id,
                template=network_template,
                subnet=network_subnet,
                host_device=network_host_device,
                accessible=network_template.accessible
            )
            network.set_is_dmz(network_template.is_dmz)
            challenge.add_network(network)

        for local_connection_id, machine_template in enumerate(network_template.connected_machines.values()):
            client_mac = generate_mac_address(challenge.id, local_network_id, local_connection_id)
            client_ip = random.choice(list(available_client_ips))
            available_client_ips.remove(client_ip)

            machine = machine_template.child

            if machine is None:
                raise ValueError("Machine ID not found")

            with db_conn.cursor() as cursor:
                cursor.execute("""
                INSERT INTO network_connections (machine_id, network_id, client_mac, client_ip)
                VALUES (%s, %s, %s, %s)
                """, (machine.id, network.id, client_mac, client_ip))

                connection = Connection(machine=machine, network=network, client_mac=client_mac, client_ip=client_ip)
                challenge.add_connection(connection)
                network.add_connection(connection)
                machine.add_connection(connection)


def create_domains(challenge_template, challenge, db_conn):
    """
    Create domains for the given challenge.
    """

    for domain_template in challenge_template.domain_templates.values():
        machine = domain_template.machine_template.child

        with db_conn.cursor() as cursor:
            cursor.execute("""
            INSERT INTO domains (machine_id, domain_name)
            VALUES (%s, %s)
            """, (machine.id, domain_template.domain))

            domain = Domain(machine=machine, domain=domain_template.domain)
            challenge.add_domain(domain)

            machine.add_domain(domain)


def create_network_devices(challenge):
    """
    Configure network devices for the given challenge and user ID.
    """

    for network in challenge.networks.values():
        create_network_api_call(network)

    reload_network_api_call()


def fetch_user_vpn_ip(user_id, db_conn):
    """
    Fetch the VPN IP address for the given user ID.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT vpn_static_ip FROM users WHERE id = %s", (user_id,))
        user_vpn_ip = cursor.fetchone()[0]

    if user_vpn_ip is None:
        raise ValueError("User VPN IP not found")

    return user_vpn_ip


def add_iptables_rules(challenge, user_vpn_ip):
    """
    Update iptables rules for the given user VPN IP.
    """
    for network in challenge.networks.values():
        # Allow intra-network traffic
        subprocess.run(
            ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", network.host_device, "-j", "ACCEPT"],
            check=True)

        # Allow DNS traffic to the router IP
        subprocess.run(
            ["iptables", "-A", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "udp", "--dport",
             "53", "-j", "ACCEPT"], check=True)
        subprocess.run(
            ["iptables", "-A", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-p", "tcp", "--dport",
             "53", "-j", "ACCEPT"], check=True)

        # Disallow traffic to the router IP
        subprocess.run(["iptables", "-A", "INPUT", "-i", network.host_device, "-d", network.router_ip, "-j", "DROP"],
                       check=True)

        if network.accessible:
            for network_connection in network.connections.values():
                # Allow traffic from the user VPN IP to the client IP
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-i", "tun0", "-o", network.host_device, "-s", user_vpn_ip, "-d",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], check=True)
                subprocess.run(
                    ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", "tun0", "-d", user_vpn_ip, "-s",
                     network_connection.client_ip, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j",
                     "ACCEPT"], check=True)

            # Disallow traffic to the router IP
            subprocess.run(["iptables", "-A", "INPUT", "-i", "tun0", "-d", network.router_ip, "-j", "DROP"],
                           check=True)

        if network.is_dmz:
            # Allow traffic from the DMZ to the outside
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network.subnet, "-o", "vmbr0", "-j", "MASQUERADE"],
                check=True)
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", network.host_device, "-o", "vmbr0", "-s", network.subnet, "-m",
                 "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", "vmbr0", "-o", network.host_device, "-d", network.subnet, "-m",
                 "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)


def wait_for_networks_to_be_up(challenge):
    """
    Wait for networks to be up.
    """

    host_devices = [network.host_device for network in challenge.networks.values()]
    all_devices_up = False

    while not all_devices_up:
        all_devices_up = True
        for device in host_devices:
            if not os.path.exists(f"/sys/class/net/{device}"):
                all_devices_up = False
                break


def start_dnsmasq_instances(challenge, user_vpn_ip):
    """
    Start a dnsmasq process per network that needs DNS/DHCP, isolated by interface.
    Each instance will only answer for its configured domains and will ignore unknown zones,
    causing the client to move to the next nameserver on timeout rather than receiving NXDOMAIN.
    """

    machines_with_user_routes = {}
    machines_with_internet_access = {}

    # Collect upstream DNS servers per machine
    dns_servers_by_machine = {machine_id: [] for machine_id in challenge.machines.keys()}
    for machine in challenge.machines.values():
        for connection in machine.connections.values():
            dns_servers_by_machine[machine.id].append(connection.network.router_ip)

    for network in challenge.networks.values():
        config_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.conf")
        pidfile_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.pid")
        leases_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.leases")
        log_path = os.path.join(DNSMASQ_INSTANCES_DIR, f"dnsmasq_{network.host_device}.log")

        with open(config_path, "w") as f:
            # Interface binding
            f.write(f"interface={network.host_device}\n")
            f.write("bind-interfaces\n")
            f.write("except-interface=lo\n")

            # DHCP range and router option
            f.write(f"dhcp-range={network.available_start_ip},{network.available_end_ip},24h\n")
            f.write(f"dhcp-option=option:router,{network.router_ip}\n")

            # Ensure dnsmasq only answers known domains and ignores unknown
            f.write("no-resolv\n")          # ignore /etc/resolv.conf
            f.write("no-poll\n")            # don't poll resolv.conf

            # For each connected machine, set DHCP and DNS behavior
            for connection in network.connections.values():
                tag = f"{connection.machine.id}"

                # DHCP host mapping and per-machine DNS
                f.write(f"dhcp-host={connection.client_mac},{connection.client_ip},set:{tag}\n")
                upstream = ",".join(dns_servers_by_machine[connection.machine.id])

                # Fallback to public DNS only if desired
                f.write(f"dhcp-option=tag:{tag},option:dns-server,{upstream},8.8.8.8,8.8.4.4\n")

                # Static route for first eligible machine
                if connection.machine.id not in machines_with_user_routes and network.accessible:
                    machines_with_user_routes[connection.machine.id] = connection
                    f.write(f"dhcp-option=tag:{tag},option:classless-static-route,{user_vpn_ip}/32,"
                            f"{network.router_ip}\n")

                if network.is_dmz:
                    if connection.machine.id not in machines_with_internet_access:
                        machines_with_internet_access[connection.machine.id] = connection
                        f.write(f"dhcp-option=tag:{tag},option:classless-static-route,0.0.0.0/0,{network.router_ip}\n")

                # Add only authoritative server for each domain
                for domain in connection.machine.domains:
                    f.write(f"address=/{domain}/{connection.client_ip}\n")

        # Launch the isolated dnsmasq instance
        subprocess.Popen([
            "dnsmasq",
            f"--conf-file={config_path}",
            f"--pid-file={pidfile_path}",
            f"--dhcp-leasefile={leases_path}",
            f"--log-facility={log_path}",
        ])


def attach_networks_to_vms(challenge):
    """
    Attach networks to virtual machines.
    """

    for machine in challenge.machines.values():
        attach_networks_to_vm_api_call(machine)


def launch_machines(challenge):
    """
    Launch machines.
    """

    for machine in challenge.machines.values():
        launch_vm_api_call(machine)


def add_running_challenge_to_user(challenge, user_id, db_conn):
    """
    Add the running challenge to the user.
    """

    with db_conn.cursor() as cursor:
        cursor.execute("UPDATE users SET running_challenge = %s WHERE id = %s", (challenge.id, user_id))
        db_conn.commit()


def undo_launch_challenge(challenge, user_id, user_vpn_ip, db_conn):
    """
    Undo the launch of a challenge by stopping and deleting the machines and networks.
    """

    if challenge is None:
        return

    stop_and_delete_machines(challenge)
    delete_network_devices(challenge)
    delete_iptables_rules(challenge, user_vpn_ip)
    stop_dnsmasq_instances(challenge)
    remove_database_entries(user_id, challenge, db_conn)


def stop_and_delete_machines(challenge):
    """
    Stop and delete the machines for a challenge.
    """

    for machine in challenge.machines.values():
        try:
            stop_vm_api_call(machine.id)
        except Exception:
            pass

        try:
            delete_vm_api_call(machine)
        except Exception:
            pass


def delete_network_devices(challenge):
    """
    Delete network devices for the given challenge.
    """

    for network in challenge.networks.values():
        try:
            delete_network_api_call(network)
        except Exception:
            pass
