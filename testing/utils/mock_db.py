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


class MockDatabase:
    def __init__(self):
        self.postgresql = None
        self.conn = None

        self.postgresql = testing.postgresql.Postgresql(
            copy_data_from=TESTING_DATABASE_BASE_DIR,
            initdb=INITDB_PATH,
            postgres=POSTGRES_PATH,
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
