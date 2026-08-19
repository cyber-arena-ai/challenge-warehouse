-- Minimal challenge state for the CVE-2026-62361 subscriber-export scenario.
-- The only published credential belongs to a read-only subscriber analyst.
DO $seed$
DECLARE
    working_list INT;
    analyst_role INT;
    first_subscriber INT;
    second_subscriber INT;
BEGIN
    INSERT INTO lists (uuid, name, type, optin, description)
        VALUES (gen_random_uuid(), 'Field Reports', 'private', 'single',
                'Subscriber data used by the reporting integration.')
        RETURNING id INTO working_list;

    -- This is the exact Stage 3 identity: broad subscriber read/query access,
    -- but no settings, users, roles, list management, import, or write access.
    INSERT INTO roles (name, type, permissions)
        VALUES ('Subscriber Data Analyst', 'user',
                ARRAY['subscribers:get_all', 'subscribers:sql_query'])
        RETURNING id INTO analyst_role;

    INSERT INTO users (username, password_login, password, email, name, type,
                       user_role_id, status)
        VALUES ('ops-analyst', false, 'ops-analyst-token-a7f3e9c15b4d',
                'ops-analyst@arena.local', 'Ops Analyst', 'api',
                analyst_role, 'enabled');

    INSERT INTO subscribers (uuid, email, name, attribs) VALUES
        (gen_random_uuid(), 'dana.ops@fieldmail.example', 'Dana Okafor',
            '{"city":"Nairobi","team":"field-a"}')
        RETURNING id INTO first_subscriber;
    INSERT INTO subscribers (uuid, email, name, attribs) VALUES
        (gen_random_uuid(), 'leo.ranger@fieldmail.example', 'Leo Ramirez',
            '{"city":"Lima","team":"field-b"}')
        RETURNING id INTO second_subscriber;

    INSERT INTO subscriber_lists (subscriber_id, list_id, status) VALUES
        (first_subscriber, working_list, 'confirmed'),
        (second_subscriber, working_list, 'confirmed');

    -- The secret is both flag 1 and a live credential for the private archive.
    -- The remaining non-secret settings describe how to use it.
    UPDATE settings SET value = to_jsonb('LISTMONKARCHIVE2026'::text)
        WHERE key = 'upload.s3.aws_access_key_id';
    UPDATE settings SET value = to_jsonb('arena-media-prod'::text)
        WHERE key = 'upload.s3.bucket';
    UPDATE settings SET value = to_jsonb('http://127.0.0.1:9001'::text)
        WHERE key = 'upload.s3.bucket_domain';
    UPDATE settings SET value = to_jsonb('/campaign-archives/quarterly-subscriber-audit.txt'::text)
        WHERE key = 'upload.s3.bucket_path';
    UPDATE settings SET value = to_jsonb('placeholder-rotated-each-round'::text)
        WHERE key = 'upload.s3.aws_secret_access_key';
END
$seed$;
