import psycopg2
from dotenv import load_dotenv
import os
import subprocess

import sys
SETUP_FILES_DIR = "/root/ctf-challenger/setup_files"
sys.path.append(SETUP_FILES_DIR)
from backup_db import backup_database, DATABASE_BACKUP_DIR
from restore_db import restore_database

load_dotenv()

DATABASE_FILES_DIR = os.getenv("DATABASE_FILES_DIR", "/root/ctf-challenger/database")
DATABASE_NAME = os.getenv("DATABASE_NAME", "ctf_challenger")
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_PORT = os.getenv("DATABASE_PORT", "5432")
DATABASE_HOST = os.getenv("DATABASE_HOST", "10.0.0.102")


class TestDatabase:
    def __init__(self):
        self.pre_test_backup_path = None
        self.backup_path = None
        self.conn = psycopg2.connect(
            host=DATABASE_HOST,
            database=DATABASE_NAME,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            port=DATABASE_PORT
        )

    def __enter__(self):
        latest_backup_path = os.path.join(DATABASE_BACKUP_DIR, "latest.backup")
        if os.path.exists(latest_backup_path):
            subprocess.run(["mv", latest_backup_path, f"{latest_backup_path}.bak"], check=True)
            self.pre_test_backup_path = f"{latest_backup_path}.bak"

        self.backup_path = backup_database("pre_test_backup")

        return self.conn

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            print(f"An error occurred: {exc_value}")

        self.reset_database()
        self.conn.close()

    def __del__(self):
        """
        Ensure the database is reset when the TestDatabase instance is deleted.
        """
        self.reset_database()
        self.conn.close()

    def reset_database(self):
        """
        Reset the database by dropping all tables and recreating them.
        """
        restore_database(self.backup_path)

        subprocess.run(["rm", "-f", self.backup_path], check=True)
        if self.pre_test_backup_path and os.path.exists(self.pre_test_backup_path):
            subprocess.run(["mv", self.pre_test_backup_path, os.path.join(DATABASE_BACKUP_DIR, "latest.backup")], check=True)