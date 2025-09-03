import requests
from dotenv import load_dotenv
import os

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")


def create_user(username, email, password):
    url = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/backend/signup.php"
    params = {
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password
    }

    response = requests.post(url, data=params)
    if response.status_code == 200:
        raise Exception(f"Failed to create user {username}: {response.text}")
