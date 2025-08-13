import subprocess
import sys
import os
import time

TEST_UTILS_DIR = "/root/ctf-challenger/testing/utils"
BACKEND_DIR = "/root/ctf-challenger/backend"

sys.path.append(TEST_UTILS_DIR)
sys.path.append(BACKEND_DIR)

from mock_db import MockDatabase
from test_challenge_template_setup import test_plain_ubuntu_setup
from create_user_config import create_user_config
from delete_user_config import delete_user_config
from import_machine_templates import import_machine_templates
from delete_machine_templates import delete_machine_templates
from launch_challenge import launch_challenge
from stop_challenge import stop_challenge
from proxmox_api_calls import vm_exists_api_call, vm_is_stopped_api_call, network_device_exists_api_call
from DatabaseClasses import Challenge, Machine, Network, Connection, Domain
from check import check
from scapy.all import sr1, IP, ICMP


def test_backend_challenge_handling():
    """
    Test the launch_challenge and stop_challenge functions.
    """

    with MockDatabase() as db_conn:
        creator_id, challenge_template = test_plain_ubuntu_setup(db_conn)

        # Create the user config
        create_user_config(creator_id, db_conn)

        # Import machine templates
        import_machine_templates(challenge_template.id, db_conn)

        print(f"\tTesting challenge launch")
        try:
            # Launch the challenge
            launch_challenge(challenge_template.id, creator_id, db_conn)

            time.sleep(10)  # Wait for the challenge to be launched

            challenge_id = None
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT running_challenge FROM users WHERE id = %s", (creator_id,))
                result = cursor.fetchone()
            if result:
                challenge_id = result[0]

            check(
                challenge_id is not None,
                "\t\tChallenge ID retrieved successfully",
                "\t\tFailed to retrieve challenge ID from database"
            )

            with db_conn.cursor() as cursor:
                cursor.execute("SELECT challenge_template_id, subnet FROM challenges WHERE id = %s", (challenge_id,))
                result = cursor.fetchone()
                check(
                    result is not None,
                    "\t\tChallenge template ID and subnet retrieved successfully",
                    "\t\tFailed to retrieve challenge template ID and subnet from database"
                )

            challenge_template_id, subnet = result
            check(
                challenge_template_id == challenge_template.id,
                "\t\tChallenge template ID matches the expected value",
                "\t\tChallenge template ID does not match the expected value"
            )
            check(
                subnet is not None,
                "\t\tSubnet retrieved successfully",
                "\t\tFailed to retrieve subnet from database"
            )

            challenge = Challenge(challenge_id, challenge_template, subnet)

            with db_conn.cursor() as cursor:
                for machine_template in challenge_template.machine_templates.values():
                    cursor.execute("SELECT id FROM machines WHERE challenge_id = %s AND machine_template_id = %s",
                                   (challenge_id, machine_template.id))
                    result = cursor.fetchall()
                    check(
                        result is not None,
                        "\t\tMachine IDs retrieved successfully",
                        "\t\tFailed to retrieve machine IDs from database"
                    )

                    for row in result:
                        machine_id = row[0]
                        machine = Machine(machine_id, machine_template, challenge)
                        challenge.add_machine(machine)



            check(
                len(challenge.machines) == len(challenge_template.machine_templates),
                "\t\tNumber of machines in database matches the number of machine templates",
                "\t\tNumber of machines in database does not match the number of machine templates"
            )

            for machine in challenge.machines.values():
                check(
                    vm_exists_api_call(machine),
                    f"\t\tMachine {machine.id} exists after launch",
                    f"\t\tMachine {machine.id} does not exist after launch"
                )
                check(
                    not vm_is_stopped_api_call(machine),
                    f"\t\tMachine {machine.id} is running after launch",
                    f"\t\tMachine {machine.id} is not running after launch"
                )

            for network_template in challenge_template.network_templates.values():
                with db_conn.cursor() as cursor:
                    cursor.execute("SELECT n.id, n.subnet, n.host_device, nt.accessible FROM networks n, "
                                   "network_templates nt WHERE nt.id = n.network_template_id AND nt.id = %s",
                                   (network_template.id,))
                    result = cursor.fetchall()

                    for id, subnet, host_device, accessible in result:
                        network = Network(id, network_template, subnet, host_device, accessible)
                        challenge.add_network(network)

            check(
                len(challenge.networks) == len(challenge_template.network_templates),
                "\t\tNumber of networks in database matches the number of network templates",
                "\t\tNumber of networks in database does not match the number of network templates"
            )

            for network in challenge.networks.values():
                check(
                    network_device_exists_api_call(network),
                    f"\t\tNetwork {network.host_device} exists in Proxmox",
                    f"\t\tNetwork {network.host_device} does not exist in Proxmox"
                )
                check(
                    os.path.exists(f"/sys/class/net/{network.host_device}"),
                    f"\t\tNetwork {network.host_device} interface exists on the host",
                    f"\t\tNetwork {network.host_device} interface does not exist on the host"
                )
                check(
                    os.path.exists(f"/etc/dnsmasq-instances/dnsmasq_{network.host_device}.conf"),
                    f"\t\tNetwork {network.id} configuration file exists",
                    f"\t\tNetwork {network.id} configuration file does not exist"
                )
                check(
                    os.path.exists(f"/etc/dnsmasq-instances/dnsmasq_{network.host_device}.pid"),
                    f"\t\tNetwork {network.id} dnsmasq instance is running",
                    f"\t\tNetwork {network.id} dnsmasq instance is not running"
                )
                pid = open(f"/etc/dnsmasq-instances/dnsmasq_{network.host_device}.pid").read().strip()
                check(
                    os.path.exists(f"/proc/{pid}"),
                    f"\t\tNetwork {network.id} dnsmasq process exists",
                    f"\t\tNetwork {network.id} dnsmasq process does not exist"
                )

            with db_conn.cursor() as cursor:
                cursor.execute("SELECT machine_id, network_id, client_mac, client_ip FROM network_connections")
                result = cursor.fetchall()

                for machine_id, network_id, client_mac, client_ip in result:
                    machine = challenge.machines.get(machine_id)
                    network = challenge.networks.get(network_id)

                    if machine and network:
                        connection = Connection(machine, network, client_mac, client_ip)
                        challenge.add_connection(connection)
                        machine.add_connection(connection)
                        network.add_connection(connection)


            with db_conn.cursor() as cursor:
                for machine in challenge.machines.values():
                    cursor.execute("SELECT domain_name from domains WHERE machine_id = %s", (machine.id,))
                    result = cursor.fetchall()
                    for domain_name in result:
                        domain = Domain(machine, domain_name[0])
                        challenge.add_domain(domain)
                        machine.add_domain(domain)

            for connection in challenge.connections.values():
                packet = IP(dst=connection.client_ip) / ICMP()

                timeout = 30
                start_time = time.time()
                response = None
                while time.time() - start_time < timeout:
                    response = sr1(packet, verbose=0, timeout=1)
                    if response is not None:
                        break

                check(
                    response is not None,
                    f"\t\tPing to {connection.client_ip} successful",
                    f"\t\tPing to {connection.client_ip} failed"
                )

            for machine in challenge.machines.values():
                for domain in machine.domains:
                    for connection in machine.connections.values():
                        stdout = subprocess.run(
                            ["dig", f"@{connection.network.router_ip}", domain.domain_name, "+short"],
                            check=True,
                            capture_output=True
                        ).stdout.decode().strip()

                        check(
                            stdout == connection.client_ip,
                            f"\t\tDNS resolution for {domain.domain_name} matches {connection.client_ip}",
                            f"\t\tDNS resolution for {domain.domain_name} does not match {connection.client_ip}"
                        )

            vpn_ip = None
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT vpn_static_ip FROM users WHERE id = %s", (creator_id,))
                result = cursor.fetchone()
            if result:
                vpn_ip = result[0]



            print("\tChallenge launched successfully")

        except Exception as e:
            print(f"\tFailed to launch challenge: {e}")

        finally:
            try:
                print("\tTesting challenge stop")
                # Stop the challenge
                stop_challenge(creator_id, db_conn)

                with db_conn.cursor() as cursor:
                    cursor.execute("SELECT running_challenge FROM users WHERE id = %s", (creator_id,))
                    result = cursor.fetchone()[0]

                check(
                    result is None,
                    "\t\tUser's running challenge set to None after stop",
                    "\t\tUser's running challenge is not None after stop"
                )

                for machine in challenge.machines.values():
                    check(
                        not vm_exists_api_call(machine),
                        f"\t\tMachine {machine.id} has been deleted after challenge stop",
                        f"\t\tMachine {machine.id} still exists after challenge stop"
                    )

                print("\tChallenge stopped successfully")

            except Exception as e:
                print(f"\tFailed to stop challenge: {e}")

            finally:
                delete_machine_templates(challenge_template.id, db_conn)

                delete_user_config(creator_id)

                db_conn.close()


if __name__ == "__main__":
    test_backend_challenge_handling()


