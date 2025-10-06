CREATE FUNCTION get_expired_challenge_data()
RETURNS TABLE (
    user_id INT,
    username TEXT,
    challenge_id INT,
    challenge_template_id INT,
    expires_at TIMESTAMP
)
BEGIN
    RETURN QUERY
    SELECT
        u.id AS user_id,
        u.username,
        c.id AS challenge_id,
        c.challenge_template_id,
        c.expires_at
    FROM users u
    JOIN challenges c ON u.running_challenge = c.id
    WHERE c.expires_at <= CURRENT_TIMESTAMP;
END;
$$;
