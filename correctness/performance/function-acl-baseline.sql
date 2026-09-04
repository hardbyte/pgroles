
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type,
            pg_get_userbyid(p.proowner) AS owner_name,
            pg_get_userbyid(acl.grantor) AS grantor
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY(ARRAY['bench_1'])
          AND grantee.rolname = ANY(ARRAY['bench_01','bench_02','bench_03','bench_04','bench_05','bench_06','bench_07','bench_08','bench_09','bench_10','bench_11','bench_12','bench_13','bench_14','bench_15','bench_16','bench_17','bench_18','bench_19','bench_20','bench_21','bench_22','bench_23','bench_24','bench_25','bench_26','bench_27','bench_28','bench_29','bench_30','bench_31','bench_32','bench_33','bench_34','bench_35','bench_36','bench_37','bench_38','bench_39','bench_40'])
        