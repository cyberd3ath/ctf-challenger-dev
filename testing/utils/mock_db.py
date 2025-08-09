import psycopg2
import testing.postgresql
from dotenv import load_dotenv
import os

load_dotenv()

TESTING_DATABASE_BASE_DIR = os.getenv("TESTING_DATABASE_BASE_DIR", "/tmp/pg_test_base")



class MockDatabase:
    def __init__(self):
        self.postgresql = None
        self.conn = None

        original_getuid = os.getuid
        os.getuid = lambda: 1000  # fake non-root UID
        self.postgresql = testing.postgresql.Postgresql(base_dir=TESTING_DATABASE_BASE_DIR)
        os.getuid = original_getuid

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
