import sys
from dotenv import load_dotenv
import os
import psycopg2
import subprocess
import random

load_dotenv()

BACKEND_DIR = "/root/ctf-challenger/backend"
sys.path.append(BACKEND_DIR)

DB_HOST = os.getenv("DATABASE_HOST")
DB_PORT = os.getenv("DATABASE_PORT")
DB_NAME = os.getenv("DATABASE_NAME")
DB_USER = os.getenv("DATABASE_USER")
DB_PASSWORD = os.getenv("DATABASE_PASSWORD")

TESTUSER_USERNAME = "testuser"
TESTUSER_EMAIL = "test@test.com"
TESTUSER_PASSWORD = "admin123"
TESTUSER_VPN_STATIC_IP = "10.64.0.2"

TEST_OVA_DIR = "/root/ctf-challenger/setup/test_ova"
TEST_OVA_FILENAME = "DC-1.ova"
TEST_OVA_PATH = os.path.join(TEST_OVA_DIR, TEST_OVA_FILENAME)
TEST_OVA_DOWNLOAD_URL = "https://heibox.uni-heidelberg.de/f/36ce12c72cc24bac81a3/?dl=1"


def insert_test_user(db_conn):
    """
    Generate a test user with a known username, email, and password.
    """

    with db_conn.cursor() as cursor:
        TESTUSER_PASSWORD_SALT = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        TESTUSER_PASSWORD_HASH = hashlib.sha512((TESTUSER_SALT + TESTUSER_PASSWORD).encode('utf-8')).hexdigest()

        cursor.execute(
            "INSERT INTO users (username, email, password_hash, password_salt, vpn_static_ip) VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (TESTUSER_USERNAME, TESTUSER_EMAIL, TESTUSER_PASSWORD_HASH, TESTUSER_PASSWORD_SALT, TESTUSER_VPN_STATIC_IP
        )
        user_id = cursor.fetchone()[0]
        db_conn.commit()

        cursor.execute(
            "UPDATE vpn_static_ips SET user_id = %s WHERE vpn_static_ip = %s",
            (user_id, TESTUSER_VPN_STATIC_IP)
        )

        db_conn.commit()

    print(f"Test user created:")
    print(f"\tUser ID: {user_id}")
    print(f"\tUsername: {TESTUSER_USERNAME}")
    print(f"\tEmail: {TESTUSER_EMAIL}")
    print(f"\tPassword: {TESTUSER_PASSWORD}")

    from get_user_config import get_user_config
    config_path = get_user_config(user_id, db_conn)

    print(f"\tUser vpn config created at {config_path}\n")

    return user_id


def download_test_ova():
    """
    Download the test OVA file from the specified URL.
    """

    if not os.path.exists(TEST_OVA_DIR):
        os.makedirs(TEST_OVA_DIR)

    if not os.path.exists(TEST_OVA_PATH):
        print(f"Downloading test OVA file from {TEST_OVA_DOWNLOAD_URL}...")
        subprocess.run(["wget", TEST_OVA_DOWNLOAD_URL, "-O", TEST_OVA_PATH], check=True, capture_output=True)
        print(f"Test OVA file downloaded to {TEST_OVA_PATH}\n")


def insert_test_ova(db_conn):
    """
    Insert a test OVA file into the database.
    """

    if not os.path.exists(TEST_OVA_PATH):
        print(f"Test OVA file not found at {TEST_OVA_PATH}.")
        download_test_ova()

    with db_conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO disk_files (user_id, display_name, proxmox_filename) VALUES (%s, %s, %s) RETURNING id",
            (1, "DC-1 - test", TEST_OVA_FILENAME)
        )

        disk_file_id = cursor.fetchone()[0]

        db_conn.commit()

    return disk_file_id


def generate_challenges(db_conn):
    """
    Generate challenges in the database.
    """

    challenge_ids = []
    machine_ids = []
    network_ids = []

    base_challenge_name = "DC-"

    combinations = [
        ("web", "easy"),
        ("web", "medium"),
        ("web", "hard"),
        ("web", "medium"),
        ("web", "hard"),
    ]

    for i, combination in enumerate(combinations):
        category, difficulty = combination
        with db_conn.cursor() as cursor:
            challenge_name = f"{base_challenge_name}{i + 1} - {category} - {difficulty}"
            challenge_description = f"Test challenge {i + 1} - {category} - {difficulty}"
            creator_id = 1
            hint = f"Hint for challenge {i + 1}"
            solution = f"Solution for challenge {i + 1}"

            cursor.execute(
                "INSERT INTO challenge_templates (name, description, category, difficulty, creator_id, hint, solution) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (challenge_name, challenge_description,
                 category, difficulty,
                 creator_id, hint,
                 solution)
            )
            challenge_id = cursor.fetchone()[0]
            db_conn.commit()

            print(f"Test challenge created:")
            print(f"\tChallenge ID: {challenge_id}")
            print(f"\tName: {challenge_name}")
            print(f"\tDescription: {challenge_description}")
            print(f"\tCategory: {category}")
            print(f"\tDifficulty: {difficulty}")
            print(f"\tCreator ID: {creator_id}")
            print(f"\tHint: {hint}")
            print(f"\tSolution: {solution}")

            challenge_ids.append(challenge_id)

    for challenge_id in challenge_ids:
        with db_conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO machine_templates (challenge_template_id, name, disk_file_path, cores, ram_gb) "
                "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (challenge_id, f"DC-1 - {challenge_id}", TEST_OVA_PATH, 1, 1, 8)
            )
            machine_template_id = cursor.fetchone()[0]
            db_conn.commit()
            print(f"Test machine template created:")
            print(f"\tMachine Template ID: {machine_template_id}")
            print(f"\tChallenge ID: {challenge_id}")
            print(f"\tName: DC-1 - {challenge_id}")
            print(f"\tDisk File Path: {TEST_OVA_PATH}")
            print(f"\tCores: 1")
            print(f"\tRAM GB: 1")
            print(f"\tDisk Size GB: 8\n")

            machine_ids.append(machine_template_id)

    for challenge_id in challenge_ids:
        with db_conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO network_templates (name, accessible, is_dmz) "
                "VALUES (%s, %s, %s) RETURNING id",
                (f"DC-1 - {challenge_id}", True, True)
            )
            network_template_id = cursor.fetchone()[0]

            db_conn.commit()
            print(f"Test network template created:")
            print(f"\tNetwork Template ID: {network_template_id}")
            print(f"\tChallenge ID: {challenge_id}")
            print(f"\tName: DC-1 - {challenge_id}")
            print(f"\tAccessible: 1")
            print(f"\tIs DMZ: 1\n")

            network_ids.append(network_template_id)

    for machine_id, network_id in zip(machine_ids, network_ids):
        with db_conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO network_connection_templates (machine_template_id, network_template_id) "
                "VALUES (%s, %s)",
                (machine_id, network_id)
            )

            db_conn.commit()
            print(f"Test network connection template created:")
            print(f"\tMachine Template ID: {machine_id}")
            print(f"\tNetwork Template ID: {network_id}\n")

    for machine_id in machine_ids:
        with db_conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO domain_templates (machine_template_id, domain_name) "
                "VALUES (%s, %s)",
                (machine_id, f"dc1-{machine_id}.local")
            )
            db_conn.commit()

        print(f"Test domain template created:")
        print(f"\tMachine Template ID: {machine_id}")
        print(f"\tDomain Name: dc1-{machine_id}.local\n")

    for challenge_id in challenge_ids:
        for flag_id in range(challenge_id):
            with db_conn.cursor() as cursor:
                flag = f"flag{flag_id}"
                description = f"Test flag {flag_id} for challenge {challenge_id}"
                points = 100 * (flag_id + 1)
                order_index = flag_id

                cursor.execute(
                    "INSERT INTO challenge_flags (challenge_template_id, flag, description, points, order_index) "
                    "VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (challenge_id, flag, description, points, order_index)
                )

            print(f"Test flag created:")
            print(f"\tChallenge ID: {challenge_id}")
            print(f"\tFlag: {flag}")
            print(f"\tDescription: {description}")
            print(f"\tPoints: {points}")
            print(f"\tOrder Index: {order_index}\n")

            db_conn.commit()

    for challenge_id in challenge_ids:
        for hint_id in range(challenge_id + 1):
            with db_conn.cursor() as cursor:
                hint_text = f"Hint {hint_id} for challenge {challenge_id}"
                unlock_points = max(0, hint_id * 100 - 50)
                order_index = hint_id

                cursor.execute(
                    "INSERT INTO challenge_hints (challenge_template_id, hint_text, unlock_points, order_index) "
                    "VALUES (%s, %s, %s, %s) RETURNING id",
                    (challenge_id, hint_text, unlock_points, order_index)
                )
                db_conn.commit()
                print(f"Test hint created:")
                print(f"\tChallenge ID: {challenge_id}")
                print(f"\tHint Text: {hint_text}")
                print(f"\tUnlock Points: {unlock_points}")
                print(f"\tOrder Index: {order_index}\n")

    from import_machine_templates import import_machine_templates

    for challenge_id in challenge_ids:
        import_machine_templates(challenge_id, db_conn)
        print(f"Test disk images imported to VM templates for challenge ID: {challenge_id}")


def main():
    """
    Main function to set up the testing environment.
    """

    db_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

    print("Connected to the database.")

    insert_test_user(db_conn)
    insert_test_ova(db_conn)
    generate_challenges(db_conn)

    db_conn.close()


if __name__ == "__main__":
    main()
