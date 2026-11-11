-- infra/postgres/roles.sql
-- Role Separation & Security Hardening for Multi-Tenant Enterprise RAG
--
-- Roles:
-- 1. rag_user: Migration / Schema Owner (executes DDL, owns tables)
-- 2. rag_app:  Application Runtime Role (NOSUPERUSER, NOBYPASSRLS, cannot alter tables or bypass RLS)

-- Create application role if it does not already exist (password set parameterized via apply_roles.py)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rag_app') THEN
        CREATE ROLE rag_app WITH
            LOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    ELSE
        -- Ensure NOBYPASSRLS and NOSUPERUSER are strictly enforced even if role existed
        ALTER ROLE rag_app WITH
            NOSUPERUSER
            NOBYPASSRLS
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION;
    END IF;
END $$;

-- Database connection privileges
GRANT CONNECT ON DATABASE rag_enterprise_db TO rag_app;

-- Schema usage privileges
GRANT USAGE ON SCHEMA public TO rag_app;

-- DML privileges on existing tenant tables (NO DDL: cannot CREATE/DROP/ALTER)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rag_app;

-- Sequence privileges (for auto-incrementing counters/sequences if any)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO rag_app;

-- Future tables / sequences created by migration owner (rag_user) automatically grant DML to rag_app
ALTER DEFAULT PRIVILEGES FOR ROLE rag_user IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO rag_app;

ALTER DEFAULT PRIVILEGES FOR ROLE rag_user IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO rag_app;
