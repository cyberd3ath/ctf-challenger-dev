import requests
from dotenv import load_dotenv
import os

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")


def get_authenticated_session(username, password):
    url = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/login.php"
    params = {
        "username": username,
        "password": password
    }

    session = requests.Session()
    response = session.post(url, data=params)
    if response.status_code != 200:
        raise Exception(f"Failed to log in user {username}: {response.text}")

    return session
