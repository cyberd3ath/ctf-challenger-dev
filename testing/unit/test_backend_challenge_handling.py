import sys
import os
import time

TEST_UTILS_DIR = "/root/ctf-challenger/testing/utils"
BACKEND_DIR = "/root/ctf-challenger/backend"

sys.path.append(TEST_UTILS_DIR)
sys.path.append(BACKEND_DIR)

from test_db import TestDatabase
from test_challenge_template_setup import test_plain_ubuntu_setup
from import_machine_templates import import_machine_templates
from delete_machine_templates import delete_machine_templates
from launch_challenge import launch_challenge
from stop_challenge import stop_challenge
from proxmox_api_calls import vm_exists_api_call, vm_is_stopped_api_call
from DatabaseClasses import Challenge, Machine, Network, Connection, Domain


def test_backend_challenge_handling():
    """
    Test the launch_challenge and stop_challenge functions.
    """

    print("\nTesting launch_challenge function")
    with MockDatabase() as db_conn:
        creator_id, challenge_template = test_plain_ubuntu_setup(db_conn)

        try:
            # Import machine templates
            import_machine_templates(challenge_template.id, db_conn)

            # Launch the challenge
            launch_challenge(challenge_template.id, creator_id, db_conn)

            challenge_id = None
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT running_challenge_id FROM users WHERE id = %s", (creator_id,))
                result = cursor.fetchone()
            if result:
                challenge_id = result[0]

            assert challenge_id is not None, "\tChallenge ID is None after launch"

            with db_conn.cursor() as cursor:
                cursor.execute("SELECT challenge_template_id, subnet FROM challenges WHERE id = %s", (challenge_id,))
                result = cursor.fetchone()
                assert result is not None, "\tChallenge not found in database after launch"

            challenge_template_id, subnet = result
            assert challenge_template_id == challenge_template.id, "\tChallenge template ID does not match after launch"
            assert subnet is not None, "\tSubnet is None after launch"

            challenge = Challenge(challenge_id, challenge_template_id, subnet)

            machines = []
            with db_conn.cursor() as cursor:
                for machine_template in challenge_template.machine_templates.values():
                    cursor.execute("SELECT id FROM machines WHERE challenge_id = %s AND machine_template_id = %s",
                                   (challenge_id, machine_template.id))
                    result = cursor.fetchall()
                    assert result, f"\tNo machines found for challenge ID {challenge_id} and machine template ID {machine_template.id}"

                    for row in result:
                        machines.append(Machine(row[0], machine_template, challenge))



            assert len(machines) == len(challenge_template.machine_templates), \
                f"\tExpected {len(challenge_template.machine_templates)} machines, found {len(machines)}"

            for machine in machines:
                assert vm_exists_api_call(machine), f"\tMachine {machine.id} does not exist after launch"
                assert not vm_is_stopped_api_call(machine), f"\tMachine {machine.id} is stopped after launch"

            print("\tChallenge launched successfully")

        except Exception as e:
            print(f"\tFailed to launch challenge: {e}")

        finally:
            print("\tTesting stop_challenge function")
            try:
                # Stop the challenge
                stop_challenge(challenge_id, db_conn)

                with db_conn.cursor() as cursor:
                    cursor.execute("SELECT running_challenge_id FROM users WHERE id = %s", (creator_id,))
                    result = cursor.fetchone()
                assert result is None, "\tUser still has a running challenge after stop"

                for machine in machines:
                    assert vm_is_stopped_api_call(machine), f"\tMachine {machine.id} is not stopped after challenge stop"

                print("\tChallenge stopped successfully")

            except Exception as e:
                print(f"\tFailed to stop challenge: {e}")
            finally:
                # Ensure the database connection is closed
                db_conn.close()


if __name__ == "__main__":
    test_backend_challenge_handling()


