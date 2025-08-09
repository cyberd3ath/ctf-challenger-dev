import psycopg2
import testing.postgresql


class MockDatabase:
    def __init__(self, init_sql_path="/root/ctf-challenger/database/init.sql"):
        self.init_sql_path = init_sql_path
        self.postgresql = None
        self.conn = None

        self.postgresql = testing.postgresql.Postgresql()
        dsn = self.postgresql.dsn()
        self.conn = psycopg2.connect(**dsn)

        with self.conn.cursor() as cursor, open(self.init_sql_path, "r") as f:
            cursor.execute(f.read())
        self.conn.commit()

    def __enter__(self):
        return self.conn

    def __del__(self):
        if self.conn:
            self.conn.close()
        if self.postgresql:
            self.postgresql.stop()
