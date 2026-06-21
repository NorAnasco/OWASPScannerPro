"""
Module de gestion de la base de donnees SQLite pour OWASP Scanner
"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
import threading


db_write_lock = threading.Lock()


class Database:
    """Gestionnaire de base de donnees SQLite"""
    
    def __init__(self, db_path: str = "database/scanner.db"):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        """Retourne une connexion a la base de donnees"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Permet d'acceder aux colonnes par nom
        return conn
    
    def get_user_by_username(self, username):
        """Récupère un utilisateur et son rôle depuis la BDD"""
        conn = self.get_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return dict(user)
        return None
    
    def create_initial_user(self, username, password_hash, role='auditor'):
        """Script utilitaire pour injecter un utilisateur (Admin ou Auditeur)"""
        #conn = get_db_connection()
        conn = self.get_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, password_hash, role)
            )
            conn.commit()
            print(f"[+] Utilisateur '{username}' créé avec le rôle '{role}'.")
        except sqlite3.IntegrityError:
            print(f"[-] L'utilisateur '{username}' existe déjà.")
        finally:
            conn.close()

    def create_project(self, project_id: str, name: str, client: str, environment: str,
                       description: str, start_date: str, end_date: str, created_by: str):
        """Crée un projet d'audit"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO projects (id, name, client, environment, description, start_date, end_date, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, name, client, environment, description, start_date or None, end_date or None, created_by)
            )
            conn.commit()
            conn.close()

    def update_project(self, project_id: str, name: str, client: str, environment: str,
                       description: str, start_date: str, end_date: str):
        """Met a jour un projet d'audit"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE projects
                SET name = ?, client = ?, environment = ?, description = ?, start_date = ?, end_date = ?
                WHERE id = ?
                """,
                (name, client, environment, description, start_date or None, end_date or None, project_id)
            )
            conn.commit()
            conn.close()

    def list_projects(self) -> list:
        """Liste tous les projets"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_project(self, project_id: str) -> dict:
        """Recupere un projet"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def delete_project(self, project_id: str):
        """Supprime un projet sans supprimer les scans"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE scans SET project_id = NULL WHERE project_id = ?", (project_id,))
            cursor.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            conn.commit()
            conn.close()

    def get_project_stats(self, project_id: str = None, created_by: str = None) -> dict:
        """Recupere les statistiques d'un projet ou globales"""
        conn = self.get_connection()
        cursor = conn.cursor()
        if project_id:
            where = "WHERE s.project_id = ?"
            params = [project_id]
        elif created_by:
            where = "WHERE s.created_by = ?"
            params = [created_by]
        else:
            where = ""
            params = []
        cursor.execute(f"SELECT COUNT(*) FROM scans s {where}", params)
        total_scans = cursor.fetchone()[0]
        cursor.execute(f"SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id {where}", params)
        total_findings = cursor.fetchone()[0]
        cursor.execute(f"SELECT AVG(score) FROM scans s {where} AND status = 'done'", params)
        avg_score = cursor.fetchone()[0] or 0
        cursor.execute(f"SELECT risk_level, COUNT(*) FROM scans s {where} GROUP BY risk_level", params)
        risk_distribution = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "avg_score": round(avg_score, 1),
            "risk_distribution": risk_distribution
        }

    def init_db(self):
        """Initialise la base de donnees avec le schema"""
        # Charger le schema SQL
        schema_path = Path(__file__).parent / "schema.sql"
        
        if not schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {schema_path}")
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = f.read()
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Executer le schema
        cursor.executescript(schema)
        conn.commit()
        conn.close()
        
        self._apply_migrations()
        
        print(f"[+] Base de donnees initialisee: {self.db_path}")
    
    def _column_exists(self, table: str, column: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table})")
        columns = [row[1] for row in cursor.fetchall()]
        conn.close()
        return column in columns
    
    def _apply_migrations(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        migrations = [
            ("findings", "annotation_status", "ALTER TABLE findings ADD COLUMN annotation_status TEXT DEFAULT 'none'"),
            ("findings", "annotation_comment", "ALTER TABLE findings ADD COLUMN annotation_comment TEXT"),
            ("findings", "annotated_by", "ALTER TABLE findings ADD COLUMN annotated_by TEXT"),
            ("findings", "annotated_at", "ALTER TABLE findings ADD COLUMN annotated_at TIMESTAMP"),
            ("scans", "project_id", "ALTER TABLE scans ADD COLUMN project_id TEXT"),
        ]
        for table, column, sql in migrations:
            if not self._column_exists(table, column):
                cursor.execute(sql)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_annotation_status ON findings(annotation_status)")
        conn.commit()
        conn.close()
    
    # ─── SCANS ────────────────────────────────────────────────────────────
    
    def save_scan(self, scan_id: str, target: str, tools: list, owasp_ids: list, created_by: str = None, project_id: str = None):
        """Sauvegarde un nouveau scan (avec created_by et project_id si fournis)"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                INSERT INTO scans (id, target, tools, owasp_ids, project_id, status, created_by)
                VALUES (?, ?, ?, ?, ?, 'running', ?)
                """,
                (scan_id, target, json.dumps(tools), json.dumps(owasp_ids), project_id, created_by or 'anonymous')
            )
            conn.commit()
            conn.close()
    
    def get_scan(self, scan_id: str) -> dict:
        """Recupere les details d'un scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def list_scans(self, limit: int = 50, offset: int = 0,
                   date_from: str = None, date_to: str = None,
                   tool: str = None, score_min: int = None,
                   score_max: int = None, project_id: str = None,
                   created_by: str = None) -> list:
        """Liste tous les scans avec filtres avancés"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT s.*, p.name as project_name, p.client as project_client
            FROM scans s
            LEFT JOIN projects p ON p.id = s.project_id
            WHERE 1=1
        """
        params = []
        if date_from:
            query += " AND date(s.started_at) >= date(?)"
            params.append(date_from)
        if date_to:
            query += " AND date(s.started_at) <= date(?)"
            params.append(date_to)
        if tool:
            query += " AND s.tools LIKE ?"
            params.append(f'%"{tool}"%')
        if score_min is not None:
            query += " AND s.score >= ?"
            params.append(score_min)
        if score_max is not None:
            query += " AND s.score <= ?"
            params.append(score_max)
        if project_id:
            query += " AND s.project_id = ?"
            params.append(project_id)
        if created_by:
            query += " AND s.created_by = ?"
            params.append(created_by)
        
        query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        scans = []
        for row in rows:
            scan_dict = dict(row)
            # Correction : On convertit le texte de la DB en vrai tableau python/JSON
            if scan_dict.get('tools'):
                try:
                    scan_dict['tools'] = json.loads(scan_dict['tools'])
                except Exception:
                    pass
            if scan_dict.get('owasp_ids'):
                try:
                    scan_dict['owasp_ids'] = json.loads(scan_dict['owasp_ids'])
                except Exception:
                    pass
            scans.append(scan_dict)
        return scans
    
    def update_scan_status(self, scan_id: str, status: str, error: str = None):
        """Met a jour le status d'un scan"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if status == "done":
                cursor.execute(
                    """
                    UPDATE scans 
                    SET status = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, scan_id)
                )
            elif status == "error":
                cursor.execute(
                    """
                    UPDATE scans 
                    SET status = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, error, scan_id)
                )
            else:
                cursor.execute(
                    "UPDATE scans SET status = ? WHERE id = ?",
                    (status, scan_id)
                )
            
            conn.commit()
            conn.close()
    
    def update_scan_results(self, scan_id: str, score: int, risk_level: str):
        """Mise a jour des resultats d'un scan"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                UPDATE scans 
                SET score = ?, risk_level = ?
                WHERE id = ?
                """,
                (score, risk_level, scan_id)
            )
            conn.commit()
            conn.close()
    
    def delete_scan(self, scan_id: str):
        """Supprime un scan (et tous ses findings)"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            conn.close()
    
    # ─── FINDINGS ─────────────────────────────────────────────────────────
    
    def save_finding(self, scan_id: str, finding: dict):
        """Sauvegarde une vulnerabilite trouvee"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                INSERT INTO findings 
                (scan_id, owasp_id, nom, outil, statut, technique, detail, preuve, cvss, remediation, source, annotation_status, annotation_comment, annotated_by, annotated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', NULL, NULL, NULL)
                """,
                (
                    scan_id,
                    finding.get("owasp_id"),
                    finding.get("nom"),
                    finding.get("outil"),
                    finding.get("statut"),
                    finding.get("technique"),
                    finding.get("detail"),
                    finding.get("preuve"),
                    finding.get("cvss"),
                    finding.get("remediation"),
                    finding.get("source"),
                    None,
                    None,
                    None,
                    None
                )
            )
            conn.commit()
            conn.close()
    
    def save_findings(self, scan_id: str, findings: list):
        """Sauvegarde plusieurs vulnerabilites en une seule transaction"""
        if not findings:
            return
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            rows = [
                (
                    scan_id,
                    f.get("owasp_id"),
                    f.get("nom"),
                    f.get("outil"),
                    f.get("statut"),
                    f.get("technique"),
                    f.get("detail"),
                    f.get("preuve"),
                    f.get("cvss"),
                    f.get("remediation"),
                    f.get("source")
                )
                for f in findings
            ]
            cursor.executemany(
                """
                INSERT INTO findings 
                (scan_id, owasp_id, nom, outil, statut, technique, detail, preuve, cvss, remediation, source, annotation_status, annotation_comment, annotated_by, annotated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'none', NULL, NULL, NULL)
                """,
                rows
            )
            conn.commit()
            conn.close()
    
    def get_findings_for_scan(self, scan_id: str) -> list:
        """Recupere tous les findings d'un scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """
            SELECT f.*, COALESCE(fc.comments, '') as comments
            FROM findings f
            LEFT JOIN (
                SELECT finding_id, GROUP_CONCAT(comment, char(10)) as comments
                FROM finding_comments
                GROUP BY finding_id
            ) fc ON fc.finding_id = f.id
            WHERE f.scan_id = ?
            ORDER BY f.cvss DESC
            """,
            (scan_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def annotate_finding(self, finding_id: int, status: str, comment: str, username: str):
        """Met a jour l'annotation d'un finding et ajoute un commentaire"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE findings
                SET annotation_status = ?, annotation_comment = ?, annotated_by = ?, annotated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (status, comment or None, username or 'anonymous', finding_id)
            )
            if comment:
                cursor.execute(
                    """
                    INSERT INTO finding_comments (finding_id, comment, created_by)
                    VALUES (?, ?, ?)
                    """,
                    (finding_id, comment, username or 'anonymous')
                )
            conn.commit()
            conn.close()
    
    def get_finding_comments(self, finding_id: int) -> list:
        """Recupere les commentaires d'un finding"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, comment, created_by, created_at
            FROM finding_comments
            WHERE finding_id = ?
            ORDER BY created_at ASC
            """,
            (finding_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    # ─── BATCHES & DIFFS ──────────────────────────────────────────────────
    
    def save_scan_batch(self, batch_id: str, targets: list, scan_ids: list, created_by: str = 'anonymous'):
        """Enregistre un lot de scans multi-cibles"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_batches (id, targets, scan_ids, created_by)
                VALUES (?, ?, ?, ?)
                """,
                (batch_id, json.dumps(targets), json.dumps(scan_ids), created_by)
            )
            conn.commit()
            conn.close()
    
    def update_scan_batch_status(self, batch_id: str, status: str, error: str = None):
        """Met a jour le statut d'un lot de scans"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            if status == 'done':
                cursor.execute(
                    """
                    UPDATE scan_batches
                    SET status = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, batch_id)
                )
            elif status == 'error':
                cursor.execute(
                    """
                    UPDATE scan_batches
                    SET status = ?, error_message = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (status, error, batch_id)
                )
            else:
                cursor.execute(
                    "UPDATE scan_batches SET status = ? WHERE id = ?",
                    (status, batch_id)
                )
            conn.commit()
            conn.close()
    
    def get_scan_batch(self, batch_id: str) -> dict:
        """Recupere un lot de scans"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_batches WHERE id = ?", (batch_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        result = dict(row)
        for key in ('targets', 'scan_ids'):
            if result.get(key):
                try:
                    result[key] = json.loads(result[key])
                except Exception:
                    pass
        return result
    
    def save_scan_diff(self, left_scan_id: str, right_scan_id: str, diff: dict, created_by: str = 'anonymous'):
        """Sauvegarde une comparaison de scans"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scan_diffs (left_scan_id, right_scan_id, diff_json, created_by)
                VALUES (?, ?, ?, ?)
                """,
                (left_scan_id, right_scan_id, json.dumps(diff, ensure_ascii=False), created_by)
            )
            conn.commit()
            conn.close()
    
    # ─── EVENEMENTS ───────────────────────────────────────────────────────
    
    def log_event(self, scan_id: str, event_type: str, message: str, 
                  phase: str = None, progress: int = None):
        """Enregistre un evenement de scan"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                INSERT INTO scan_events (scan_id, event_type, message, phase, progress)
                VALUES (?, ?, ?, ?, ?)
                """,
                (scan_id, event_type, message, phase, progress)
            )
            conn.commit()
            conn.close()
    
    def get_events_for_scan(self, scan_id: str) -> list:
        """Recupere les evenements d'un scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM scan_events WHERE scan_id = ? ORDER BY timestamp ASC",
            (scan_id,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    # ─── RESULTATS ────────────────────────────────────────────────────────
    
    def save_results(self, scan_id: str, target: str, tools_used: list, 
                    score: int, risk_level: str, stats: dict):
        """Sauvegarde les resultats consolides d'un scan"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                INSERT OR REPLACE INTO scan_results 
                (scan_id, target, tools_used, score, risk_level, stats)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    json.dumps(tools_used),
                    score,
                    risk_level,
                    json.dumps(stats)
                )
            )
            conn.commit()
            conn.close()
    
    def get_results(self, scan_id: str) -> dict:
        """Recupere les resultats consolides d'un scan"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            result = dict(row)
            # Deserializer les JSON
            if result.get('tools_used'):
                result['tools_used'] = json.loads(result['tools_used'])
            if result.get('stats'):
                result['stats'] = json.loads(result['stats'])
            return result
        return None
    
    # ─── STATISTIQUES ─────────────────────────────────────────────────────
    
    def get_stats(self) -> dict:
        """Recupere les statistiques globales"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Nombre de scans par status
        cursor.execute(
            "SELECT status, COUNT(*) as count FROM scans GROUP BY status"
        )
        status_stats = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Nombre total de scans
        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]
        
        # Nombre total de findings
        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]
        
        # Score moyen
        cursor.execute("SELECT AVG(score) FROM scans WHERE status = 'done'")
        avg_score = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "avg_score": round(avg_score, 1),
            "scans_by_status": status_stats
        }
    
    # ─── NETTOYAGE ────────────────────────────────────────────────────────
    
    def cleanup_old_scans(self, days: int = 30):
        """Supprime les anciens scans (> X jours)"""
        with db_write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                """
                DELETE FROM scans 
                WHERE completed_at IS NOT NULL 
                AND datetime(completed_at) < datetime('now', '-' || ? || ' days')
                """,
                (days,)
            )
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            return deleted
