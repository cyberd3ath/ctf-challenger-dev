import os
import math
import requests
from dotenv import load_dotenv
import time

load_dotenv()

SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_PROTOCOL = os.getenv("SERVER_PROTOCOL", "https")

API_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/upload-diskfile.php"
CONFIG_URL = f"{SERVER_PROTOCOL}://{SERVER_HOST}:{SERVER_PORT}/config/general.config.json"


def load_config():
    response = requests.get(CONFIG_URL)
    if response.status_code != 200:
        raise Exception(f"Failed to load config: {response.text}")
    return response.json()["upload"]


def init_upload(file_path, session, chunk_size, target_filename=None):
    uploadId = f"temp_{int(time.time() * 1000)}"
    file_name = os.path.basename(file_path) if not target_filename else target_filename
    file_size = os.path.getsize(file_path)
    total_chunks = math.ceil(file_size / chunk_size)
    init_payload = {
        "phase": "init",
        "uploadId": uploadId,
        "fileName": file_name,
        "fileSize": file_size,
        "totalChunks": total_chunks
    }
    response = session.post(API_URL, json=init_payload)
    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to initialize upload: {response.text}")

    return uploadId, total_chunks


def upload_chunk_by_chunk(file_path, session, uploadId, chunk_size, total_chunks):
    for chunk_index in range(total_chunks):
        with open(file_path, "rb") as f:
            f.seek(chunk_index * chunk_size)
            chunk_data = f.read(chunk_size)

        upload_data = {
            "phase": "chunk",
            "uploadId": uploadId,
            "chunkIndex": chunk_index,
            "chunk": chunk_data
        }

        response = session.post(API_URL, data=upload_data)
        if response.status_code != 200 or not response.json().get("success"):
            raise Exception(f"Failed to upload chunk {chunk_index}: {response.text}")

        print(f"Uploaded chunk {chunk_index + 1}/{total_chunks}")


def finalize_upload(uploadId, session):
    finalize_payload = {
        "phase": "finalize",
        "uploadId": uploadId
    }
    response = session.post(API_URL, json=finalize_payload)
    if response.status_code != 200 or not response.json().get("success"):
        raise Exception(f"Failed to finalize upload: {response.text}")
    print("Upload finalized successfully.")


def upload_file(file_path, session, target_filename=None):
    config = load_config()
    chunk_size = config.get("CHUNK_SIZE", 1048576)

    uploadId, total_chunks = init_upload(file_path, session, chunk_size, target_filename)
    upload_chunk_by_chunk(file_path, session, uploadId, chunk_size, total_chunks)
    finalize_upload(uploadId, session)
