import os
import sqlite3
from werkzeug.security import generate_password_hash


# Repère le dossier où se trouve init_db.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "database", "scanner.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "database" ,"schema.sql") # Remplace par le nom exact de ton fichier SQL si besoin

def init_database():
    # Assurer que le dossier 'database' existe
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    db_exists = os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)

    if not db_exists:
        # 1. Base neuve : exécuter tout le schéma SQL
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        print("[+] Nouvelle base de données créée avec succès.")
        
        # 2. Créer les utilisateurs par défaut
        admin_hash = generate_password_hash("Admin123!")
        auditor_hash = generate_password_hash("Auditeur123!")

        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", admin_hash, "admin")
        )
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("auditeur", auditor_hash, "auditor")
        )
        conn.commit()
        print("[+] Comptes par défaut injectés :")
        print("    -> Login: admin    | MDP: Admin123!    (Rôle: admin)")
        print("    -> Login: auditeur | MDP: Auditeur123! (Rôle: auditor)")
    else:
        # 3. Base existante : ajouter les tables manquantes (migration)
        print("[*] Base existante détectée. Mise à jour de la structure...")
        
        # Appliquer le schema complet (CREATE IF NOT EXISTS est sécurisé)
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        
        # Vérifier si app_config a des valeurs, en insérer si vide
        row = conn.execute("SELECT COUNT(*) FROM app_config").fetchone()
        if row[0] == 0:
            defaults = [
                ('nmap_real', 'false'), ('zap_real', 'false'), ('nikto_real', 'false'), ('burp_real', 'false'),
                ('zap_host', '127.0.0.1'), ('zap_port', '8080'),
                ('burp_host', '127.0.0.1'), ('burp_port', '1337'),
                ('debug_mode', 'false')
            ]
            for key, value in defaults:
                conn.execute("INSERT INTO app_config (key, value) VALUES (?, ?)", (key, value))
            conn.commit()
            print("[+] Configuration par défaut initialisée.")
        
        print("[✓] Migration terminée.")

    conn.close()

if __name__ == "__main__":
    init_database()