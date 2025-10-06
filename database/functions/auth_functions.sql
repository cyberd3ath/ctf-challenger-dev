CREATE FUNCTION is_username_taken(p_username TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM users WHERE users.username = p_username);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION is_email_taken(p_email TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS(SELECT 1 FROM users WHERE users.email = p_email);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION create_user(
    p_username TEXT,
    p_email TEXT,
    p_password_hash TEXT,
    p_password_salt TEXT
)
RETURNS TABLE (
    id INT,
    vpn_static_ip INET
) AS $$
DECLARE
    v_user_id INT;
    v_vpn_ip INET;
BEGIN
    v_user_id := allocate_user_id();

    INSERT INTO users (username, email, password_hash, password_salt, id)
    VALUES (p_username, p_email, p_password_hash, p_password_salt, v_user_id);

    v_vpn_ip := assign_lowest_vpn_ip(v_user_id);
    UPDATE users u SET vpn_static_ip = v_vpn_ip WHERE u.id = v_user_id;

    RETURN QUERY
    SELECT v_user_id AS id, v_vpn_ip AS vpn_static_ip;
END;
$$ LANGUAGE plpgsql;



CREATE FUNCTION update_last_login(p_user_id INT)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET last_login = CURRENT_TIMESTAMP
    WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION get_user_password_salt(p_username TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN (SELECT password_salt FROM users WHERE username = p_username);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION authenticate_user(
    p_username TEXT,
    p_password_hash TEXT
)
RETURNS INT AS $$
DECLARE
    v_user_id INT;
BEGIN
    SELECT id INTO v_user_id
    FROM users
    WHERE username = p_username AND password_hash = p_password_hash;
    RETURN v_user_id;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION change_user_password(
    p_user_id INT,
    p_old_password_hash TEXT,
    p_new_password_hash TEXT,
    p_new_password_salt TEXT
)
RETURNS VOID AS $$
BEGIN
    UPDATE users
    SET password_hash = p_new_password_hash,
        password_salt = p_new_password_salt
    WHERE id = p_user_id AND password_hash = p_old_password_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Old password does not match';
    END IF;
END;
$$ LANGUAGE plpgsql;
