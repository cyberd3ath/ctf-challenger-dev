import psycopg2
import testing.postgresql
from dotenv import load_dotenv
import os

load_dotenv()

TESTING_DATABASE_BASE_DIR = os.getenv("TESTING_DATABASE_BASE_DIR", "/tmp/pg_test_base")

POSTGRES_BINARIES_PATHS = None
for path in [
    "/usr/lib/postgresql/16/bin",
    "/usr/lib/postgresql/15/bin",
    "/usr/lib/postgresql/14/bin",
    "/usr/lib/postgresql/13/bin"
]:
    if os.path.exists(path):
        POSTGRES_BINARIES_PATHS = path
        break

INITDB_PATH = os.path.join(POSTGRES_BINARIES_PATHS, "initdb") if POSTGRES_BINARIES_PATHS else None
POSTGRES_PATH = os.path.join(POSTGRES_BINARIES_PATHS, "postgres") if POSTGRES_BINARIES_PATHS else None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WRAPPER_DIR = os.path.join(SCRIPT_DIR, "pg_wrappers")
INITDB_WRAPPER = os.path.join(WRAPPER_DIR, "initdb-sudo")
POSTGRES_WRAPPER = os.path.join(WRAPPER_DIR, "postgres-sudo")

if not (os.path.exists(INITDB_WRAPPER) and os.path.exists(POSTGRES_WRAPPER)):
    os.makedirs(WRAPPER_DIR, exist_ok=True)

    def create_wrapper(path, real_path):
        with open(path, "w") as f:
            f.write(f"#!/bin/bash\nexec sudo -u postgres {real_path} \"$@\"\n")
        os.chmod(path, 0o755)

    create_wrapper(INITDB_WRAPPER, INITDB_PATH)
    create_wrapper(POSTGRES_WRAPPER, POSTGRES_PATH)

class MockDatabase:
    def __init__(self):
        self.postgresql = None
        self.conn = None

        self.postgresql = testing.postgresql.Postgresql(
            copy_data_from=TESTING_DATABASE_BASE_DIR,
            initdb=INITDB_WRAPPER,
            postgres=POSTGRES_WRAPPER,
        )

        dsn = self.postgresql.dsn()
        self.conn = psycopg2.connect(**dsn)

    def __enter__(self):
        return self.conn

    def __exit__(self, exc_type, exc_value, traceback):
        if self.conn:
            self.conn.close()
        if self.postgresql:
            self.postgresql.stop()

    def __del__(self):
        self.__exit__(None, None, None)
