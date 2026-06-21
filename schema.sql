-- ═══════════════════════════════════════════════════════════════
-- OWASP Scanner Pro — Schéma de Base de Données SQLite (Corrigé)
-- ═══════════════════════════════════════════════════════════════

-- Table: Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'auditor',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT,
    environment TEXT DEFAULT 'prod',
    description TEXT,
    start_date TEXT,
    end_date TEXT,
    created_by TEXT DEFAULT 'anonymous',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(created_by) REFERENCES users(username) ON DELETE SET DEFAULT
);
CREATE INDEX IF NOT EXISTS idx_projects_name ON projects(name);
CREATE INDEX IF NOT EXISTS idx_projects_created ON projects(created_at);

-- Table: Scans
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    tools TEXT NOT NULL,
    owasp_ids TEXT NOT NULL,
    project_id TEXT,
    status TEXT DEFAULT 'running',
    score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'Moyen',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,
    created_by TEXT DEFAULT 'anonymous',
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE SET NULL,
    FOREIGN KEY(created_by) REFERENCES users(username) ON DELETE SET DEFAULT
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(started_at);

-- Table: Findings
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    owasp_id TEXT NOT NULL,
    nom TEXT NOT NULL,
    outil TEXT NOT NULL,
    statut TEXT NOT NULL,
    technique TEXT,
    detail TEXT,
    preuve TEXT,
    cvss REAL,
    remediation TEXT,
    source TEXT,
    annotation_status TEXT DEFAULT 'none',
    annotation_comment TEXT,
    annotated_by TEXT,
    annotated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_owasp ON findings(owasp_id);
CREATE INDEX IF NOT EXISTS idx_findings_statut ON findings(statut);

CREATE TABLE IF NOT EXISTS finding_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    comment TEXT NOT NULL,
    created_by TEXT DEFAULT 'anonymous',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_finding_comments_finding ON finding_comments(finding_id);

CREATE TABLE IF NOT EXISTS scan_batches (
    id TEXT PRIMARY KEY,
    created_by TEXT DEFAULT 'anonymous',
    status TEXT DEFAULT 'running',
    targets TEXT NOT NULL,
    scan_ids TEXT NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS scan_diffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    left_scan_id TEXT NOT NULL,
    right_scan_id TEXT NOT NULL,
    diff_json TEXT NOT NULL,
    created_by TEXT DEFAULT 'anonymous',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table: Evenements de scan
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    phase TEXT,
    message TEXT,
    progress INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- 🎯 Virgule ici aussi
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);

-- Table: Resultats consolides
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    tools_used TEXT,
    score INTEGER,
    risk_level TEXT,
    stats TEXT,
    report_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- 🎯 Virgule ici aussi
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);