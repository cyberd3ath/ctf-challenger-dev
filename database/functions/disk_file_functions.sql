CREATE FUNCTIOn get_user_disk_files(
    p_user_id INT
)
RETURNS TABLE (
    id INT,
    display_name TEXT,
    upload_date TIMESTAMP,
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        id,
        display_name,
        upload_date
    FROM disk_files
    WHERE user_id = p_user_id
    ORDER BY upload_date DESC, id ASC;
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION is_duplicate_file_name(
    p_user_id INT,
    p_display_name TEXT
)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM disk_files
        WHERE user_id = p_user_id
        AND display_name = p_display_name
    );
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION add_user_disk_file(
    p_user_id INT,
    p_display_name TEXT,
    p_proxmox_filename TEXT
) RETURNS VOID AS $$
BEGIN
    INSERT INTO disk_files (user_id, display_name, proxmox_filename)
    VALUES (p_user_id, p_display_name, p_proxmox_filename);
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION get_filename_by_ids(
    p_ova_id INT,
    p_user_id INT
) RETURNS TEXT AS $$
BEGIN
    RETURN (
        SELECT proxmox_filename FROM disk_files
        WHERE id = p_ova_id AND user_id = p_user_id
    );
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION delete_user_disk_file(
    p_ova_id INT,
    p_user_id INT
) RETURNS VOID AS $$
BEGIN
    DELETE FROM disk_files
    WHERE id = p_ova_id AND user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;