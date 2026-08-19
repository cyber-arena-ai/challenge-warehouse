-- Close two demonstrated PostgreSQL-function routes that otherwise read the
-- protected setting through the ordinary, validated subscriber-query endpoint.
-- They execute SQL supplied as a runtime string, so EXPLAIN cannot attribute the
-- protected relation to listmonk's table validator.
DO $executor_controls$
DECLARE
    fn RECORD;
    still_executable TEXT;
BEGIN
    FOR fn IN
        SELECT p.oid::regprocedure AS signature
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'pg_catalog'
          AND (p.proname ~ '^(query|table|cursor|schema|database)_to_xml'
               OR p.proname = 'ts_stat')
    LOOP
        EXECUTE format(
            'REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', fn.signature
        );
    END LOOP;

    SELECT string_agg(p.oid::regprocedure::text, ', ')
      INTO still_executable
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'pg_catalog'
       AND (p.proname ~ '^(query|table|cursor|schema|database)_to_xml'
            OR p.proname = 'ts_stat')
       AND has_function_privilege('listmonk', p.oid, 'EXECUTE');

    IF still_executable IS NOT NULL THEN
        RAISE EXCEPTION 'alternate SQL executor remains available: %',
            still_executable;
    END IF;
END
$executor_controls$;

-- The published SQL-expression feature can otherwise tie up the bounded
-- application connection pool with pg_sleep(). Five seconds is well above the
-- measured legitimate query/export latency and bounds this obvious DoS path.
ALTER ROLE listmonk SET statement_timeout = '5s';
