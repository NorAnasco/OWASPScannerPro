-- ═══════════════════════════════════════════════════════════════
-- OWASP Scanner Pro — Schéma de Base de Données SQLite
-- ═══════════════════════════════════════════════════════════════

-- Table: Users
-- Gestion des comptes et des niveaux d'accès (RBAC)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'auditor',   -- 'admin' | 'auditor'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index pour accélérer la vérification à la connexion
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Table: Projects
-- Regroupe les scans par client, application ou périmètre d'audit
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
-- Stocke les informations de chaque scan
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,                    -- UUID unique
    target TEXT NOT NULL,                   -- URL/domaine scannee
    tools TEXT NOT NULL,                    -- JSON: ["nmap","zap","nikto","burp","ai"]
    owasp_ids TEXT NOT NULL,                -- JSON: ["A01","A02","A03",...]
    project_id TEXT,                        -- Reference au projet
    status TEXT DEFAULT 'running',          -- running | done | error
    score INTEGER DEFAULT 0,                -- 0-100
    risk_level TEXT DEFAULT 'Moyen',        -- Critique | Eleve | Moyen | Faible
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error_message TEXT,                     -- Si erreur
    created_by TEXT DEFAULT 'anonymous',   -- Username de l'utilisateur
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE SET NULL,
    FOREIGN KEY(created_by) REFERENCES users(username) ON DELETE SET DEFAULT
);

-- Indexes pour recherche rapide
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(started_at);

-- Table: Findings
-- Les vulnerabilites decouvertes lors des scans
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,                  -- Reference au scan
    owasp_id TEXT NOT NULL,                 -- A01, A02, etc.
    nom TEXT NOT NULL,                      -- Nom de la vulnerabilite
    outil TEXT NOT NULL,                    -- Nmap, ZAP, Nikto, Burp, IA
    statut TEXT NOT NULL,                   -- critique | eleve | moyen | faible | ok
    technique TEXT,                         -- Methode de detection
    detail TEXT,                            -- Description detaillee
    preuve TEXT,                            -- Preuve (ex: GET /path -> 200)
    cvss REAL,                              -- Score CVSS
    remediation TEXT,                       -- Comment corriger
    source TEXT,                            -- Source interne (nmap_real, zap_simulated, etc.)
    annotation_status TEXT DEFAULT 'none',  -- none | faux_positif | confirme | en_correction | corrige
    annotation_comment TEXT,
    annotated_by TEXT,
    annotated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Indexes
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

CREATE INDEX IF NOT EXISTS idx_scan_diffs_left ON scan_diffs(left_scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_right ON scan_diffs(right_scan_id);

-- Table: Evenements de scan (optionnel, pour tracer la progression)
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    event_type TEXT NOT NULL,               -- phase | tool_done | done | error
    phase TEXT,                             -- init, nmap, zap, nikto, burp, ai, report
    message TEXT,
    progress INTEGER,                       -- 0-100
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);

-- Table: Resultats consolides (cache du rapport final)
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    tools_used TEXT,                        -- JSON
    score INTEGER,
    risk_level TEXT,
    stats TEXT,                             -- JSON: {critique: 5, eleve: 10, ...}
    report_json TEXT,                       -- Rapport complet en JSON (optionnel, pour archivage)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- ═══════════════════════════════════════════════════════════════
-- AUDIT & LOGGING — Nouveautés v3.0
-- ═══════════════════════════════════════════════════════════════

-- Table: Audit Logs
-- Piste d'audit exhaustive pour toutes les actions importantes
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username TEXT NOT NULL,                  -- Qui a fait l'action
    action TEXT NOT NULL,                    -- scan_start | scan_delete | user_create | user_delete | login | login_fail | logout | export | gdpr_forget
    details TEXT,                            -- JSON — contexte détaillé
    ip_address TEXT,                          -- Adresse IP source
    scan_id TEXT,                             -- Scan concerné (si applicable)
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

-- Indexes pour l'audit
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

-- ═══════════════════════════════════════════════════════════════
-- CONFIGURATION — Stockage des réglages modifiables via l'UI
-- ═══════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_by TEXT DEFAULT 'system',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Valeurs par défaut
INSERT OR IGNORE INTO app_config (key, value) VALUES ('nmap_real', 'false');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('zap_real', 'false');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('nikto_real', 'false');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('burp_real', 'false');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('zap_host', '127.0.0.1');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('zap_port', '8080');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('burp_host', '127.0.0.1');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('burp_port', '1337');
INSERT OR IGNORE INTO app_config (key, value) VALUES ('debug_mode', 'false');
