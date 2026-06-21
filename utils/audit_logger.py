"""
Module d'audit trail — enregistre toutes les actions importantes
pour la conformité RGPD et la traçabilité de sécurité.
"""
import json
import sqlite3
import os
from datetime import datetime
from functools import wraps
from flask import request, session


class AuditLogger:
    """Logger de piste d'audit pour toutes les actions sensibles."""

    ACTIONS = {
        'scan_start': 'Lancement de scan',
        'scan_delete': 'Suppression de scan',
        'scan_export': 'Export de rapport',
        'finding_annotate': 'Annotation de finding',
        'scan_diff': 'Comparaison de scans',
        'batch_scan': 'Scan multi-cibles',
        'project_create': 'Création de projet',
        'project_delete': 'Suppression de projet',
        'user_create': 'Création d\'utilisateur',
        'user_delete': 'Suppression d\'utilisateur',
        'login': 'Connexion réussie',
        'login_fail': 'Tentative de connexion échouée',
        'logout': 'Déconnexion',
        'gdpr_forget': 'Effacement RGPD (right to be forgotten)',
        'config_update': 'Mise à jour de la configuration',
    }

    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def log(self, username: str, action: str, details: dict = None,
            ip_address: str = None, scan_id: str = None):
        """
        Enregistre une action dans la table audit_logs.

        Args:
            username: Nom de l'utilisateur ayant effectué l'action
            action: Type d'action (clé de ACTIONS)
            details: Dictionnaire de contexte (JSON)
            ip_address: Adresse IP source (auto-détectée si None)
            scan_id: ID du scan concerné (optionnel)
        """
        if action not in self.ACTIONS:
            action = f"unknown_{action}"

        if ip_address is None:
            try:
                ip_address = request.remote_addr or '0.0.0.0'
            except RuntimeError:
                ip_address = '0.0.0.0'

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (username, action, details, ip_address, scan_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, action, json.dumps(details, ensure_ascii=False) if details else None,
             ip_address, scan_id)
        )
        conn.commit()
        conn.close()

    def get_logs(self, limit: int = 100, offset: int = 0,
                 action_filter: str = None, username_filter: str = None,
                 date_from: str = None, date_to: str = None) -> list:
        """Récupère les logs d'audit avec filtres optionnels."""
        conn = self._get_conn()
        cursor = conn.cursor()

        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if action_filter:
            query += " AND action = ?"
            params.append(action_filter)
        if username_filter:
            query += " AND username LIKE ?"
            params.append(f"%{username_filter}%")
        if date_from:
            query += " AND timestamp >= ?"
            params.append(date_from)
        if date_to:
            query += " AND timestamp <= ?"
            params.append(date_to)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            d = dict(row)
            if d.get('details'):
                try:
                    d['details'] = json.loads(d['details'])
                except (json.JSONDecodeError, TypeError):
                    pass
            action = d.get('action', '')
            # Générer un label plus descriptif pour les mises à jour de configuration (mode réel/simulé)
            if action == 'config_update':
                details = d.get('details', {}) or {}
                values = details.get('values', {}) or {}
                keys = details.get('keys', []) or []
                labels = []
                for k in keys:
                    v = values.get(k)
                    if k.endswith('_real') and v is not None:
                        tool_name = k.replace('_real', '').upper()
                        mode = 'Réel' if v in ('true', True) else 'Simulé'
                        labels.append(f"Mode {tool_name} : {mode}")
                    elif k in ('zap_host', 'zap_port', 'burp_host', 'burp_port'):
                        labels.append(f"{k} : {v}")
                    elif k == 'debug_mode' and v is not None:
                        labels.append(f"Mode debug : {'Activé' if v in ('true', True) else 'Désactivé'}")
                    else:
                        labels.append(f"{k} : {v}")
                if labels:
                    d['action_label'] = ' · '.join(labels)
                else:
                    d['action_label'] = self.ACTIONS.get(action, action)
            else:
                d['action_label'] = self.ACTIONS.get(action, action)
            results.append(d)
        return results

    def count_logs(self, action_filter: str = None,
                   username_filter: str = None) -> int:
        """Compte le nombre total de logs (pour pagination)."""
        conn = self._get_conn()
        cursor = conn.cursor()

        query = "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
        params = []

        if action_filter:
            query += " AND action = ?"
            params.append(action_filter)
        if username_filter:
            query += " AND username LIKE ?"
            params.append(f"%{username_filter}%")

        cursor.execute(query, params)
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def delete_user_data(self, username: str) -> dict:
        """
        RGPD — Right to be forgotten.
        Supprime toutes les traces de l'utilisateur (anonymise).
        Retourne le nombre d'enregistrements affectés.
        """
        conn = self._get_conn()
        cursor = conn.cursor()

        stats = {}

        # 1. Anonymiser les scans créés par cet utilisateur
        cursor.execute(
            "UPDATE scans SET created_by = 'anonymized' WHERE created_by = ?",
            (username,)
        )
        stats['scans_anonymized'] = cursor.rowcount

        # 2. Supprimer l'utilisateur
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        stats['user_deleted'] = cursor.rowcount

        # 3. Anonymiser les logs d'audit de cet utilisateur
        cursor.execute(
            "UPDATE audit_logs SET username = 'anonymized', details = NULL WHERE username = ?",
            (username,)
        )
        stats['audit_logs_anonymized'] = cursor.rowcount

        conn.commit()
        conn.close()

        # Loguer l'action d'effacement
        self.log('system', 'gdpr_forget', {
            'target_username': username,
            'records_affected': stats
        })

        return stats