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
from proxmox_api_calls import vm_exists_api_call, vm_is_stopped_api_call
from DatabaseClasses import Challenge, Machine, Network, Connection, Domain
from check import check


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

            challenge = Challenge(challenge_id, challenge_template_id, subnet)

            machines = []
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
                        machines.append(Machine(row[0], machine_template, challenge))



            check(
                len(machines) == len(challenge_template.machine_templates),
                "\t\tNumber of machines in database matches the number of machine templates",
                "\t\tNumber of machines in database does not match the number of machine templates"
            )

            for machine in machines:
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


                for machine in machines:
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


