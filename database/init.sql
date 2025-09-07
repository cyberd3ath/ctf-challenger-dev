-- refined init.sql (concurrency-safe, reclaim-queue + sequences)
-- Run in a transaction if you want; some DBAs prefer separate steps.

-- enable needed extension early
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-------------------------
-- Helper: random avatar
-------------------------
CREATE OR REPLACE FUNCTION generate_random_default_avatar()
RETURNS VARCHAR AS $$
BEGIN
    RETURN '/assets/avatars/avatar' || (FLOOR(1 + RANDOM() * 3))::INT::TEXT || '.png';
END;
$$ LANGUAGE plpgsql;

----------------------------------------------------------
-- 5) vpn_static_ips assign function (non-blocking with SKIP LOCKED)
----------------------------------------------------------
CREATE OR REPLACE FUNCTION assign_lowest_vpn_ip(user_id_param INT)
RETURNS INET AS $$
DECLARE
    selected_ip INET;
BEGIN
    WITH next_ip AS (
        SELECT vpn_static_ip
        FROM vpn_static_ips
        WHERE user_id IS NULL
        ORDER BY vpn_static_ip
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE vpn_static_ips
    SET user_id = user_id_param
    FROM next_ip
    WHERE vpn_static_ips.vpn_static_ip = next_ip.vpn_static_ip
    RETURNING vpn_static_ips.vpn_static_ip INTO selected_ip;

    RETURN selected_ip;
END;
$$ LANGUAGE plpgsql;


----------------------------------------------------------
-- 6) assign_challenge_subnet() - analogous to vpn ip assignment
----------------------------------------------------------
CREATE OR REPLACE FUNCTION assign_challenge_subnet()
RETURNS INET AS $$
DECLARE
    selected_subnet INET;
BEGIN
    WITH next_subnet AS (
        SELECT subnet
        FROM challenge_subnets
        WHERE available = TRUE
        ORDER BY subnet
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    UPDATE challenge_subnets
    SET available = FALSE
    FROM next_subnet
    WHERE challenge_subnets.subnet = next_subnet.subnet
    RETURNING challenge_subnets.subnet INTO selected_subnet;

    RETURN selected_subnet;
END;
$$ LANGUAGE plpgsql;

-----------------------------------------------------------
-- 1) Sequences + Reclaim queues + allocation functions
--    For tables where ID reuse matters & ranges exist:
--    users, machines, machine_templates, networks, challenges
-----------------------------------------------------------

-- USERS
CREATE SEQUENCE users_id_seq
    START 1
    MINVALUE 1
    NO CYCLE;

CREATE TABLE user_id_reclaim (
    id INTEGER PRIMARY KEY
);

CREATE OR REPLACE FUNCTION allocate_user_id()
RETURNS INTEGER AS $$
DECLARE
    new_id INTEGER;
BEGIN
    -- Try to reclaim an ID
    DELETE FROM user_id_reclaim
    WHERE id = (
        SELECT id FROM user_id_reclaim
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        new_id := nextval('users_id_seq');
    END IF;

    RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reclaim_user_id()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO user_id_reclaim (id) VALUES (OLD.id)
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;


-- MACHINES (constrained range 100000001 .. 899999999)
CREATE SEQUENCE machines_id_seq
    START 100000001
    MINVALUE 100000001
    MAXVALUE 899999999
    NO CYCLE;

CREATE TABLE machine_id_reclaim (
    id INTEGER PRIMARY KEY
);

CREATE OR REPLACE FUNCTION allocate_machine_id()
RETURNS INTEGER AS $$
DECLARE
    new_id INTEGER;
BEGIN
    DELETE FROM machine_id_reclaim
    WHERE id = (
        SELECT id FROM machine_id_reclaim
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        new_id := nextval('machines_id_seq');
    END IF;

    RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reclaim_machine_id()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO machine_id_reclaim (id) VALUES (OLD.id)
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;


-- MACHINE_TEMPLATES (constrained range 900000001 .. 999999999)
CREATE SEQUENCE machine_templates_id_seq
    START 900000001
    MINVALUE 900000001
    MAXVALUE 999999999
    NO CYCLE;

CREATE TABLE machine_template_id_reclaim (
    id INTEGER PRIMARY KEY
);

CREATE OR REPLACE FUNCTION allocate_machine_template_id()
RETURNS INTEGER AS $$
DECLARE
    new_id INTEGER;
BEGIN
    DELETE FROM machine_template_id_reclaim
    WHERE id = (
        SELECT id FROM machine_template_id_reclaim
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        new_id := nextval('machine_templates_id_seq');
    END IF;

    RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reclaim_machine_template_id()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO machine_template_id_reclaim (id) VALUES (OLD.id)
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;


-- NETWORKS (no strict range in your original schema but reuse wanted)
CREATE SEQUENCE networks_id_seq
    START 1
    MINVALUE 1
    NO CYCLE;

CREATE TABLE network_id_reclaim (
    id INTEGER PRIMARY KEY
);

CREATE OR REPLACE FUNCTION allocate_network_id()
RETURNS INTEGER AS $$
DECLARE
    new_id INTEGER;
BEGIN
    DELETE FROM network_id_reclaim
    WHERE id = (
        SELECT id FROM network_id_reclaim
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        new_id := nextval('networks_id_seq');
    END IF;

    RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reclaim_network_id()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO network_id_reclaim (id) VALUES (OLD.id)
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;


-- CHALLENGES (if you want to reuse challenge IDs)
CREATE SEQUENCE challenges_id_seq
    START 1
    MINVALUE 1
    NO CYCLE;

CREATE TABLE challenge_id_reclaim (
    id INTEGER PRIMARY KEY
);

CREATE OR REPLACE FUNCTION allocate_challenge_id()
RETURNS INTEGER AS $$
DECLARE
    new_id INTEGER;
BEGIN
    DELETE FROM challenge_id_reclaim
    WHERE id = (
        SELECT id FROM challenge_id_reclaim
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        new_id := nextval('challenges_id_seq');
    END IF;

    RETURN new_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION reclaim_challenge_id()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO challenge_id_reclaim (id) VALUES (OLD.id)
        ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

----------------------------------------------------------
-- 2) Functions to allocate other sequence-backed SERIAL ids
--    (we create explicit sequences for older SERIAL columns)
----------------------------------------------------------

-- challenge_templates.id sequence
CREATE SEQUENCE challenge_templates_id_seq START 1 MINVALUE 1 NO CYCLE;
-- network_templates.id sequence
CREATE SEQUENCE network_templates_id_seq START 1 MINVALUE 1 NO CYCLE;
-- challenge_flags.id sequence
CREATE SEQUENCE challenge_flags_id_seq START 1 MINVALUE 1 NO CYCLE;
-- challenge_hints.id sequence
CREATE SEQUENCE challenge_hints_id_seq START 1 MINVALUE 1 NO CYCLE;
-- completed_challenges.id sequence
CREATE SEQUENCE completed_challenges_id_seq START 1 MINVALUE 1 NO CYCLE;
-- badges.id sequence
CREATE SEQUENCE badges_id_seq START 1 MINVALUE 1 NO CYCLE;
-- announcements.id sequence
CREATE SEQUENCE announcements_id_seq START 1 MINVALUE 1 NO CYCLE;
-- disk_files.id sequence
CREATE SEQUENCE disk_files_id_seq START 1 MINVALUE 1 NO CYCLE;

----------------------------------------------------------
-- 3) Tables (using allocate_xxx() defaults where appropriate)
----------------------------------------------------------

CREATE TABLE vpn_static_ips (
    vpn_static_ip INET PRIMARY KEY,
    user_id INT
);

-- USERS: use allocate_user_id() as default, and trigger to reclaim
CREATE TABLE users (
    id INT PRIMARY KEY DEFAULT allocate_user_id(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(255) DEFAULT generate_random_default_avatar(),
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    last_ip VARCHAR(45),
    running_challenge INT,
    is_admin BOOLEAN DEFAULT FALSE,
    vpn_static_ip INET REFERENCES vpn_static_ips(vpn_static_ip) ON DELETE SET NULL
);

-- add trigger to reclaim user id on delete
CREATE TRIGGER trg_reclaim_user_id
AFTER DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION reclaim_user_id();

-- vpn_static_ips FK referencing users (create after users exists)
ALTER TABLE vpn_static_ips
ADD CONSTRAINT fk_user_id
FOREIGN KEY (user_id)
REFERENCES users(id) ON DELETE SET NULL;


-- challenge_templates (explicit sequence)
CREATE TABLE challenge_templates (
    id INTEGER PRIMARY KEY DEFAULT nextval('challenge_templates_id_seq'),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category TEXT NOT NULL CHECK (category IN ('web','crypto','reverse','forensics','pwn','misc')),
    difficulty TEXT NOT NULL CHECK (difficulty IN ('easy','medium','hard')),
    image_path VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    creator_id INT REFERENCES users(id) ON DELETE CASCADE,
    hint TEXT,
    solution TEXT,
    marked_for_deletion BOOLEAN DEFAULT FALSE
);

-- challenge_subnets
CREATE TABLE challenge_subnets
(
    subnet    INET    NOT NULL
        CONSTRAINT challenge_subnet_pkey
            PRIMARY KEY,
    available boolean NOT NULL
);

-- CHALLENGES: use allocate_challenge_id()
CREATE TABLE challenges (
    id INTEGER PRIMARY KEY DEFAULT allocate_challenge_id(),
    challenge_template_id INT NOT NULL,
    subnet INET REFERENCES challenge_subnets(subnet) ON DELETE CASCADE DEFAULT assign_challenge_subnet(),
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '1 hour'),
    used_extensions INT DEFAULT 0,
    FOREIGN KEY (challenge_template_id) REFERENCES challenge_templates(id) ON DELETE CASCADE
);

-- reclaim trigger for challenges
CREATE TRIGGER trg_reclaim_challenge_id
AFTER DELETE ON challenges
FOR EACH ROW
EXECUTE FUNCTION reclaim_challenge_id();

-- user running_challenge FK
ALTER TABLE users
ADD CONSTRAINT fk_running_challenge
FOREIGN KEY (running_challenge)
REFERENCES challenges(id) ON DELETE SET NULL;

-- user_profiles
CREATE TABLE user_profiles (
    user_id INT PRIMARY KEY,
    full_name VARCHAR(100),
    bio TEXT,
    github_url VARCHAR(255),
    twitter_url VARCHAR(255),
    website_url VARCHAR(255),
    country VARCHAR(50),
    timezone VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- MACHINE_TEMPLATES: allocate_machine_template_id()
CREATE TABLE machine_templates (
    id INTEGER PRIMARY KEY DEFAULT allocate_machine_template_id(),
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    disk_file_path VARCHAR(255) NOT NULL,
    cores INT NOT NULL CHECK (cores > 0),
    ram_gb INT NOT NULL CHECK (ram_gb > 0)
);

-- reclaim trigger for machine_templates
CREATE TRIGGER trg_reclaim_machine_template_id
AFTER DELETE ON machine_templates
FOR EACH ROW
EXECUTE FUNCTION reclaim_machine_template_id();

-- network_templates
CREATE TABLE network_templates (
    id INTEGER PRIMARY KEY DEFAULT nextval('network_templates_id_seq'),
    name VARCHAR(100) NOT NULL,
    accessible BOOLEAN NOT NULL,
    is_dmz BOOLEAN NOT NULL DEFAULT FALSE
);

-- domain_templates
CREATE TABLE domain_templates (
    machine_template_id INT NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (machine_template_id, domain_name)
);

-- network_connection_templates
CREATE TABLE network_connection_templates (
    machine_template_id INT NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    network_template_id INT NOT NULL REFERENCES network_templates(id) ON DELETE CASCADE,
    PRIMARY KEY (machine_template_id, network_template_id)
);

-- challenge_flags
CREATE TABLE challenge_flags (
    id INTEGER PRIMARY KEY DEFAULT nextval('challenge_flags_id_seq'),
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    flag VARCHAR(255) NOT NULL,
    description TEXT,
    points INT NOT NULL,
    order_index INT DEFAULT 0
);

-- challenge_hints
CREATE TABLE challenge_hints (
    id INTEGER PRIMARY KEY DEFAULT nextval('challenge_hints_id_seq'),
    challenge_template_id INT NOT NULL REFERENCES challenge_templates(id) ON DELETE CASCADE,
    hint_text TEXT NOT NULL,
    unlock_points INT DEFAULT 0,
    order_index INT DEFAULT 0
);

-- completed_challenges
CREATE TABLE completed_challenges (
    id INTEGER PRIMARY KEY DEFAULT nextval('completed_challenges_id_seq'),
    user_id INT NOT NULL,
    challenge_template_id INT NOT NULL,
    attempts INT NOT NULL DEFAULT 1,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    flag_id INTEGER REFERENCES challenge_flags(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (challenge_template_id) REFERENCES challenge_templates(id) ON DELETE CASCADE
);

-- badges
CREATE TABLE badges (
    id INTEGER PRIMARY KEY DEFAULT nextval('badges_id_seq'),
    name VARCHAR(50) NOT NULL,
    description TEXT,
    icon VARCHAR(20),
    color VARCHAR(20),
    rarity VARCHAR(10) DEFAULT 'common' CHECK (rarity IN ('common', 'uncommon', 'rare', 'epic', 'legendary')),
    requirements TEXT NOT NULL
);

-- user_badges
CREATE TABLE user_badges (
    user_id INT NOT NULL,
    badge_id INT NOT NULL,
    earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, badge_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (badge_id) REFERENCES badges(id) ON DELETE CASCADE
);

-- announcements
CREATE TABLE announcements (
    id INTEGER PRIMARY KEY DEFAULT nextval('announcements_id_seq'),
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    short_description VARCHAR(255),
    importance TEXT NOT NULL CHECK (importance IN ('critical','important','normal')),
    category TEXT NOT NULL CHECK (category IN ('general','updates','maintenance','events','security')),
    author VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- disk_files
CREATE TABLE disk_files (
    id INTEGER PRIMARY KEY DEFAULT nextval('disk_files_id_seq'),
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name VARCHAR(100) NOT NULL,
    proxmox_filename VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, display_name)
);

-- MACHINES: allocate_machine_id()
CREATE TABLE machines
(
    id INTEGER NOT NULL PRIMARY KEY DEFAULT allocate_machine_id(),
    machine_template_id INTEGER NOT NULL REFERENCES machine_templates(id) ON DELETE CASCADE,
    challenge_id INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE
);

-- reclaim trigger for machines
CREATE TRIGGER trg_reclaim_machine_id
AFTER DELETE ON machines
FOR EACH ROW
EXECUTE FUNCTION reclaim_machine_id();

-- NETWORKS: allocate_network_id()
CREATE TABLE networks
(
    id INTEGER NOT NULL PRIMARY KEY DEFAULT allocate_network_id(),
    network_template_id INTEGER NOT NULL REFERENCES network_templates(id) ON DELETE CASCADE,
    subnet INET NOT NULL,
    host_device VARCHAR NOT NULL
);

-- reclaim trigger for networks
CREATE TRIGGER trg_reclaim_network_id
AFTER DELETE ON networks
FOR EACH ROW
EXECUTE FUNCTION reclaim_network_id();

-- network_connections
CREATE TABLE network_connections
(
    machine_id INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    client_mac MACADDR NOT NULL,
    client_ip  INET    NOT NULL,
    PRIMARY KEY (machine_id, network_id)
);

-- domains
CREATE TABLE domains
(
    machine_id  INTEGER NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (machine_id, domain_name)
);

----------------------------------------------------------
-- 4) Indexes
----------------------------------------------------------
CREATE INDEX idx_machine_templates_challenge ON machine_templates(challenge_template_id);
CREATE INDEX idx_domain_templates_machine ON domain_templates(machine_template_id);
CREATE INDEX idx_network_connection_templates_machine ON network_connection_templates(machine_template_id);
CREATE INDEX idx_network_connection_templates_network ON network_connection_templates(network_template_id);
CREATE INDEX idx_challenge_flags_challenge ON challenge_flags(challenge_template_id);
CREATE INDEX idx_challenge_hints_challenge ON challenge_hints(challenge_template_id);
CREATE INDEX idx_completed_challenges_user_id ON completed_challenges(user_id);
CREATE INDEX idx_challenges_challenge_template_id ON challenges(challenge_template_id);
CREATE INDEX idx_announcements_importance ON announcements(importance);
CREATE INDEX idx_announcements_created_at ON announcements(created_at);
CREATE INDEX idx_disk_files_user_id ON disk_files(user_id);
CREATE INDEX idx_disk_files_upload_date ON disk_files(upload_date);

----------------------------------------------------------
-- 7) convenience: cleanup triggers / reclaim inserts exist above
--    (we already created triggers to push old IDs into reclaim tables)
----------------------------------------------------------

-- Make sure foreign key references to users(username) (announcements.author) don't fail on creation:
-- We used the column reference as before; if you plan to insert announcements before users, ensure username exists.

----------------------------------------------------------
-- 8) Seed badges (unchanged)
----------------------------------------------------------
INSERT INTO badges (name, description, icon, color, rarity, requirements)
VALUES
    ('Web Warrior', 'Solved 5 web challenges', '🕸️', 'gold', 'common', 'Solve 5 web challenges'),
    ('Crypto Expert', 'Solved 5 crypto challenges', '🔐', 'silver', 'common', 'Solve 5 crypto challenges'),
    ('Reverse Engineer', 'Solved 5 reverse challenges', '👁️', 'bronze', 'common', 'Solve 5 reverse challenges'),
    ('Forensic Analyst', 'Solved 5 forensics challenges', '🕵️', 'gold', 'common', 'Solve 5 forensics challenges'),
    ('Binary Buster', 'Solved 5 pwn challenges', '💣', 'silver', 'common', 'Solve 5 pwn challenges'),
    ('Puzzle Master', 'Solved 5 misc challenges', '🧩', 'bronze', 'common', 'Solve 5 misc challenges'),
    ('First Blood', 'First to solve a challenge', '💉', 'red', 'rare', 'Be the first to solve any challenge'),
    ('Speed Runner', 'Solved a challenge in under 5 minutes', '⚡', 'blue', 'uncommon', 'Solve any challenge in under 5 minutes'),
    ('Master Hacker', 'Earn all other badges', '👑', 'rainbow', 'legendary', 'Earn all available badges');

----------------------------------------------------------
-- 9) Notes & usage
----------------------------------------------------------
-- * Allocation behavior:
--   - On INSERT, the DEFAULT will call the appropriate allocate_*() function, which first tries
--     to pull a recycled ID from the reclaim table (DELETE ... RETURNING id with SKIP LOCKED),
--     and if none are available, falls back to nextval() from the sequence.
-- * Reclaim behavior:
--   - Triggers automatically INSERT the deleted ID into the reclaim table (ON CONFLICT DO NOTHING).
--   - This means you do NOT need to change your application delete logic; the DB reclaims IDs.
-- * Concurrency:
--   - The use of FOR UPDATE SKIP LOCKED ensures multiple concurrent allocators won't deadlock or wait
--     on the same reclaim row.
-- * Exhaustion:
--   - Sequence MAXVALUE is enforced for constrained sequences (machines & machine_templates).
--     If the sequence reaches MAXVALUE, nextval() will fail with an error. Reclaimed IDs can avoid exhaustion.
-- * Optional: GC or compaction:
--   - If you want deterministic "lowest available" allocation ordering, you might want to store a
--     created_at in reclaim tables and ORDER BY id when selecting. Currently we select LIMIT 1 (which
--     will typically return the lowest by index, but you can change to ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED).
--   - For very large reclaim sets you may want to periodically clean or reorder them.
--
-- If you want me to:
--  - Change the reclaim selection to always pick the absolute smallest reclaimed ID (ORDER BY id),
--  - Or preseed the reclaim tables with a range (NOT recommended for huge ranges),
--  - Or add monitoring helpers (views to show reclaim pool sizes / sequence usage),
-- I can add them.

