import os
from dotenv import load_dotenv
import time
import datetime

from yaml_parser import yaml_to_create_challenge_form_data
from upload_ova_file import upload_all_ova_files

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

CREATE_CHALLENGE_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/create-ctf.php"


def setup_challenge(admin_session, path_to_yaml, upload_ovas=True, prints=False):
    start_time = time.time()

    if prints:
        print("Setting up challenge from:", path_to_yaml)

    if upload_ovas:
        if prints:
            print("\nUploading all OVA files for the challenge")
        upload_all_ova_files(path_to_yaml, admin_session, prints=prints)

    if prints:
        print("\nPreparing form data from YAML")
    form_data = yaml_to_create_challenge_form_data(path_to_yaml)

    if prints:
        print("\nCreating challenge on the server")
    response = admin_session.post(CREATE_CHALLENGE_URL, data=form_data)
    challenge_id = response.json().get("challenge_id")

    end_time = time.time()

    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to create challenge: {response.text}")

    if prints:
        print(f"\nChallenge (ID {challenge_id} created successfully")
        print(f"Total time taken: {datetime.timedelta(seconds=end_time - start_time)}")

    return challenge_id


if __name__ == "__main__":
    from get_authenticated_session import get_authenticated_session

    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
    session = get_authenticated_session(ADMIN_USER, ADMIN_PASSWORD)


    YAML_PATH = os.path.abspath("yaml/ctf-config.yaml")
    setup_challenge(session, YAML_PATH, upload_ovas=False, prints=True)


