"""
Scan Scheduler — planifie des scans automatiques récurrents.
Fonctionne avec un thread background qui vérifie les tâches planifiées.
"""
import threading
import time
import json
import sqlite3
import os
from datetime import datetime, timedelta
from typing import Callable


class ScanScheduler:
    """
    Planificateur de scans automatiques.
    
    Les tâches sont stockées en base de données et exécutées
    par un thread background qui se réveille toutes les 30 secondes.
    """

    def __init__(self, db_path: str, scan_runner: Callable):
        """
        Args:
            db_path: Chemin vers la base SQLite
            scan_runner: Fonction callback pour lancer un scan
                         signature: run_scan(target, tools, owasp_ids, username) -> scan_id
        """
        self.db_path = db_path
        self.run_scan = scan_runner
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_table(self):
        """Crée la table des tâches planifiées si elle n'existe pas."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                tools TEXT NOT NULL,
                owasp_ids TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                interval_minutes INTEGER,
                next_run TIMESTAMP,
                last_run TIMESTAMP,
                last_scan_id TEXT,
                enabled INTEGER DEFAULT 1,
                created_by TEXT DEFAULT 'anonymous',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def schedule_scan(self, target: str, tools: list, owasp_ids: list,
                      interval_minutes: int = 60, created_by: str = 'anonymous') -> int:
        """
        Planifie un scan récurrent.

        Args:
            target: URL cible
            tools: Liste des outils
            owasp_ids: Liste des OWASP IDs
            interval_minutes: Intervalle en minutes entre chaque scan
            created_by: Nom de l'utilisateur

        Returns:
            ID de la tâche planifiée
        """
        next_run = datetime.now() + timedelta(minutes=interval_minutes)
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scheduled_scans 
            (target, tools, owasp_ids, interval_minutes, next_run, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target, json.dumps(tools), json.dumps(owasp_ids),
             interval_minutes, next_run.isoformat(), created_by)
        )
        conn.commit()
        task_id = cursor.lastrowid
        conn.close()
        return task_id

    def get_scheduled_scans(self) -> list:
        """Récupère toutes les tâches planifiées."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM scheduled_scans ORDER BY next_run ASC"
        )
        rows = cursor.fetchall()
        conn.close()
        results = []
        for row in rows:
            d = dict(row)
            if d.get('tools'):
                try:
                    d['tools'] = json.loads(d['tools'])
                except Exception:
                    pass
            if d.get('owasp_ids'):
                try:
                    d['owasp_ids'] = json.loads(d['owasp_ids'])
                except Exception:
                    pass
            results.append(d)
        return results

    def delete_scheduled_scan(self, task_id: int):
        """Supprime une tâche planifiée."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scheduled_scans WHERE id = ?", (task_id,))
        conn.commit()
        conn.close()

    def toggle_scheduled_scan(self, task_id: int, enabled: bool):
        """Active ou désactive une tâche planifiée."""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scheduled_scans SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, task_id)
        )
        conn.commit()
        conn.close()

    def _worker(self):
        """Thread background qui vérifie et exécute les tâches."""
        self._init_table()
        while self._running:
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                now = datetime.now()

                cursor.execute(
                    """
                    SELECT * FROM scheduled_scans 
                    WHERE enabled = 1 
                    AND next_run IS NOT NULL
                    AND datetime(next_run) <= datetime(?)
                    """,
                    (now.isoformat(),)
                )
                due_tasks = cursor.fetchall()
                conn.close()

                for task in due_tasks:
                    task = dict(task)
                    try:
                        tools = json.loads(task['tools']) if isinstance(task['tools'], str) else task['tools']
                        owasp_ids = json.loads(task['owasp_ids']) if isinstance(task['owasp_ids'], str) else task['owasp_ids']

                        # Lancer le scan
                        scan_id = self.run_scan(
                            target=task['target'],
                            tools=tools,
                            owasp_ids=owasp_ids,
                            username=task.get('created_by', 'scheduler')
                        )

                        # Mettre à jour le prochain run
                        next_run = now + timedelta(minutes=task['interval_minutes'] or 60)
                        conn2 = self._get_conn()
                        cursor2 = conn2.cursor()
                        cursor2.execute(
                            """
                            UPDATE scheduled_scans 
                            SET last_run = ?, last_scan_id = ?, next_run = ?
                            WHERE id = ?
                            """,
                            (now.isoformat(), scan_id, next_run.isoformat(), task['id'])
                        )
                        conn2.commit()
                        conn2.close()

                    except Exception as e:
                        print(f"[-] Scheduler error task {task['id']}: {e}")

            except Exception as e:
                print(f"[-] Scheduler worker error: {e}")

            # Dormir 30 secondes avant la prochaine vérification
            for _ in range(30):
                if not self._running:
                    break
                time.sleep(1)

    def start(self):
        """Démarre le thread du scheduler."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()
        print("[+] Scan scheduler démarré")

    def stop(self):
        """Arrête le thread du scheduler."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[-] Scan scheduler arrêté")