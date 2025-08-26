def test_user_setup(
        db_conn,
        username,
        password
    ):
    """
    Setup a user for testing purposes.
    """

    email = f"{username}@testusers.test"

    with db_conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, crypt(%s, gen_salt('bf'))) RETURNING id",
            (username, email, password)
        )
        user_id = cursor.fetchone()[0]

        cursor.execute(
            "UPDATE users SET vpn_static_ip=assign_lowest_vpn_ip(%s) WHERE id = %s",
            (user_id, user_id)
        )

    db_conn.commit()

    return user_id