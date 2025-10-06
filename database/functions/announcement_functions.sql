CREATE FUNCTIOn get_total_announcement_count()
RETURNS INT AS $$
BEGIN
    RETURN (SELECT COUNT(*) FROM announcements);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION get_announcements(
    p_limit INT,
    p_offset INT
)
RETURNS TABLE (
    id INT,
    title TEXT,
    content TEXT,
    short_description TEXT,
    importance announcement_importance,
    category announcement_category,
    author TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT * FROM announcements
    ORDER BY created_at DESC
    LIMIT p_limit OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION create_announcement(
    p_title TEXT,
    p_content TEXT,
    p_short_description TEXT,
    p_importance announcement_importance,
    p_category announcement_category,
    p_author TEXT
)
RETURNS INT AS $$
BEGIN
    INSERT INTO announcements (
        title,
        content,
        short_description,
        importance,
        category,
        author,
        created_at,
        updated_at
    ) VALUES (
        p_title,
        p_content,
        p_short_description,
        p_importance,
        p_category,
        p_author,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ) RETURNING id;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION update_announcement(
    p_id INT,
    p_title TEXT,
    p_content TEXT,
    p_short_description TEXT,
    p_importance announcement_importance,
    p_category announcement_category
)
RETURNS VOID AS $$
BEGIN
    UPDATE announcements
    SET
        title = p_title,
        content = p_content,
        short_description = p_short_description,
        importance = p_importance,
        category = p_category,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION announcement_exists(p_id INT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM announcements WHERE id = p_id);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION delete_announcement(p_id INT)
RETURNS VOID AS $$
BEGIN
    DELETE FROM announcements WHERE id = p_id;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION get_filtered_announcements(
    p_importance announcement_importance,
    p_date_range TEXT,
    p_limit INT,
    p_offset INT
)
RETURNS TABLE (
    id INT,
    title TEXT,
    content TEXT,
    short_description TEXT,
    importance announcement_importance,
    category announcement_category,
    author TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
) AS $$
DECLARE
    v_start_date TIMESTAMP;
BEGIN
    IF p_date_range = 'today' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 day';
    ELSIF p_date_range = 'week' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 week';
    ELSIF p_date_range = 'month' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 month';
    ELSIF p_date_range = 'year' THEN
        v_start_date := CURRENT_TIMESTAMP - INTERVAL '1 year';
    ELSE
        v_start_date := NULL;
    END IF;

    RETURN QUERY
    SELECT * FROM announcements a
    WHERE (p_importance IS NULL OR a.importance = p_importance)
      AND (v_start_date IS NULL OR a.created_at >= v_start_date)
    ORDER BY a.created_at DESC, a.id ASC
    LIMIT p_limit OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION get_filtered_announcements_count(
    p_importance announcement_importance,
    p_date_range TEXT
)
RETURNS INT AS $$
BEGIN
    RETURN COUNT(*) FROM get_filtered_announcements(
        p_importance,
        p_date_range,
        NULL,
        NULL
    );
END;
$$ LANGUAGE plpgsql;
