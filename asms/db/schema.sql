-- =====================================================================
-- ASMS — PostgreSQL schema
-- Source of truth for tenants, users, assets, scans, and vulnerabilities.
-- Raw scanner evidence lives in Elasticsearch; large artefacts in S3.
-- =====================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive text

-- ---------------------------------------------------------------------
-- Enumerated types
-- ---------------------------------------------------------------------
CREATE TYPE severity        AS ENUM ('info', 'low', 'medium', 'high', 'critical');
CREATE TYPE finding_status  AS ENUM ('open', 'in_progress', 'fixed', 'false_positive',
                                     'accepted_risk', 'wont_fix');
CREATE TYPE scan_status     AS ENUM ('queued', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE scan_type       AS ENUM ('dast', 'easm', 'api', 'mobile', 'infra',
                                     'sast', 'iac', 'compliance', 'darkweb');
CREATE TYPE asset_type      AS ENUM ('domain', 'subdomain', 'ip', 'url',
                                     'api', 'mobile_app', 'host', 'repository',
                                     'container_image', 'iac_module');
CREATE TYPE confidence      AS ENUM ('low', 'medium', 'high', 'confirmed');

-- ---------------------------------------------------------------------
-- Tenants & users
-- ---------------------------------------------------------------------
CREATE TABLE organizations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    slug         CITEXT NOT NULL UNIQUE,
    plan         TEXT NOT NULL DEFAULT 'standard',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           CITEXT NOT NULL,
    full_name       TEXT,
    role            TEXT NOT NULL CHECK (role IN ('org_admin', 'security_lead',
                                                  'engineer', 'auditor', 'api_client')),
    mfa_enrolled    BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);
CREATE INDEX idx_users_org ON users(organization_id);

-- ---------------------------------------------------------------------
-- Assets — anything we scan
-- ---------------------------------------------------------------------
CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type      asset_type NOT NULL,
    value           TEXT NOT NULL,                 -- "example.com", "https://api.x", "1.2.3.4", "git@github.com:org/repo.git"
    criticality     INT NOT NULL DEFAULT 3 CHECK (criticality BETWEEN 1 AND 5),
    tags            TEXT[] NOT NULL DEFAULT '{}',
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    discovered_by   TEXT,                          -- "easm.subdomains", "manual", "import"
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, asset_type, value)
);
CREATE INDEX idx_assets_org_type ON assets(organization_id, asset_type);
CREATE INDEX idx_assets_tags ON assets USING gin (tags);
CREATE INDEX idx_assets_meta ON assets USING gin (metadata);

-- ---------------------------------------------------------------------
-- Scans
-- ---------------------------------------------------------------------
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_type       scan_type NOT NULL,
    status          scan_status NOT NULL DEFAULT 'queued',
    requested_by    UUID REFERENCES users(id),
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    error           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_scans_org_status ON scans(organization_id, status);
CREATE INDEX idx_scans_asset ON scans(asset_id);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- ---------------------------------------------------------------------
-- Vulnerability catalogue (the "what" — independent of any one finding)
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT NOT NULL UNIQUE,          -- e.g. "missing-csp", "sqli-stacked"
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,                 -- e.g. "Security Headers", "Injection"
    cwe             TEXT,                          -- e.g. "CWE-79"
    owasp           TEXT,                          -- e.g. "A05:2021"
    default_severity severity NOT NULL,
    default_cvss     NUMERIC(3,1),                 -- 0.0 - 10.0
    remediation     TEXT NOT NULL,
    references_     JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- ---------------------------------------------------------------------
-- Vulnerabilities — the user-facing record (the fields specified in the brief)
--
-- Required fields from the brief:
--   id, type, criticality (Low/Medium/High/Critical), CVSS, description,
--   URL/parameter, status (Open / Fixed / False Positive).
--
-- We add organization/asset/scan FKs and audit columns for production use.
-- ---------------------------------------------------------------------
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id        UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    definition_id   UUID REFERENCES vulnerability_definitions(id) ON DELETE SET NULL,

    -- "type" in the brief — short, machine-friendly identifier
    type            TEXT NOT NULL,                 -- e.g. "missing-csp", "xss-reflected"

    -- criticality (Low | Medium | High | Critical) — also keep "info"
    severity        severity NOT NULL,
    cvss            NUMERIC(3,1) CHECK (cvss IS NULL OR cvss BETWEEN 0.0 AND 10.0),
    cvss_vector     TEXT,                          -- CVSS:3.1/AV:N/AC:L/...

    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    remediation     TEXT,

    -- The exact location ("URL/parameter")
    url             TEXT,
    http_method     TEXT,
    parameter       TEXT,
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,  -- request/response excerpts, payload
    confidence      confidence NOT NULL DEFAULT 'medium',

    -- Status: Open / Fixed / False Positive (+ extended)
    status          finding_status NOT NULL DEFAULT 'open',

    -- Deduplication
    fingerprint     TEXT NOT NULL,                 -- hash(asset_id || type || url || parameter || payload)

    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID REFERENCES users(id),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (organization_id, fingerprint)
);
CREATE INDEX idx_vuln_org_severity ON vulnerabilities(organization_id, severity);
CREATE INDEX idx_vuln_org_status   ON vulnerabilities(organization_id, status);
CREATE INDEX idx_vuln_asset        ON vulnerabilities(asset_id);
CREATE INDEX idx_vuln_scan         ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_type         ON vulnerabilities(type);
CREATE INDEX idx_vuln_last_seen    ON vulnerabilities(last_seen_at DESC);
CREATE INDEX idx_vuln_evidence     ON vulnerabilities USING gin (evidence);

-- Compliance mappings (PCI DSS, ISO 27001, GDPR, HIPAA, CIS, …)
CREATE TABLE compliance_frameworks (
    id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code   TEXT NOT NULL UNIQUE,                   -- "PCI-DSS-4.0", "ISO-27001:2022"
    name   TEXT NOT NULL
);

CREATE TABLE compliance_controls (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id  UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_code  TEXT NOT NULL,                   -- "6.4.2"
    description   TEXT NOT NULL,
    UNIQUE (framework_id, control_code)
);

CREATE TABLE vulnerability_compliance_links (
    vulnerability_definition_id UUID NOT NULL REFERENCES vulnerability_definitions(id) ON DELETE CASCADE,
    control_id                  UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_definition_id, control_id)
);

-- Comments / triage log per vulnerability
CREATE TABLE vulnerability_comments (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    author_id        UUID REFERENCES users(id),
    body             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_vuln_comments ON vulnerability_comments(vulnerability_id, created_at DESC);

-- Append-only audit log
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    entity_type     TEXT NOT NULL,                 -- "vulnerability", "scan", "user"
    entity_id       UUID,
    action          TEXT NOT NULL,                 -- "status_change", "create", "delete"
    before          JSONB,
    after           JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org_time ON audit_log(organization_id, created_at DESC);

-- ---------------------------------------------------------------------
-- Row-level security: enforce tenant isolation
-- ---------------------------------------------------------------------
ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets              ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans               ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities     ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerability_comments ENABLE ROW LEVEL SECURITY;

-- Session must `SET app.current_org = '<uuid>'` before querying.
CREATE POLICY users_tenant_isolation ON users
    USING (organization_id::text = current_setting('app.current_org', true));
CREATE POLICY assets_tenant_isolation ON assets
    USING (organization_id::text = current_setting('app.current_org', true));
CREATE POLICY scans_tenant_isolation ON scans
    USING (organization_id::text = current_setting('app.current_org', true));
CREATE POLICY vulns_tenant_isolation ON vulnerabilities
    USING (organization_id::text = current_setting('app.current_org', true));
CREATE POLICY vuln_comments_tenant_isolation ON vulnerability_comments
    USING (EXISTS (
        SELECT 1 FROM vulnerabilities v
        WHERE v.id = vulnerability_comments.vulnerability_id
          AND v.organization_id::text = current_setting('app.current_org', true)
    ));

-- ---------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vuln_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- Convenience view: per-org security posture
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW vw_org_posture AS
SELECT
    o.id                                       AS organization_id,
    o.name                                     AS organization_name,
    COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'critical') AS open_critical,
    COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'high')     AS open_high,
    COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'medium')   AS open_medium,
    COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'low')      AS open_low,
    COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'info')     AS open_info,
    COUNT(*) FILTER (WHERE v.status = 'fixed')                            AS fixed_total,
    COUNT(*) FILTER (WHERE v.status = 'false_positive')                   AS false_positive_total,
    -- 100 minus a weighted penalty per open finding, floored at 0.
    GREATEST(
        0,
        100 - (
              COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'critical') * 20
            + COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'high')     * 8
            + COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'medium')   * 3
            + COUNT(*) FILTER (WHERE v.status = 'open' AND v.severity = 'low')      * 1
        )
    )::INT AS security_score
FROM organizations o
LEFT JOIN vulnerabilities v ON v.organization_id = o.id
GROUP BY o.id, o.name;

COMMIT;
