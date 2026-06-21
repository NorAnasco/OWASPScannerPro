"""
Scanner Nikto — exécute nikto en sous-processus et parse la sortie.
Nikto doit être installé : sudo apt install nikto  (ou brew install nikto sur Mac)
"""
import os
import subprocess
import shutil
import re
import requests
import tempfile
from config import NIKTO_USE_REAL, NIKTO_TIMEOUT


# Fichiers/chemins sensibles à vérifier en mode simulé
# OWASP Top 10 2025 — IDs de référence mis à jour :
# A02 = Security Misconfiguration (ex-A05:2021)
# A03 = Software Supply Chain Failures (ex-A06:2021)
# A04 = Cryptographic Failures (ex-A02:2021)
# A05 = Injection (ex-A03:2021)
SENSITIVE_PATHS = [
    # A02:2025 Security Misconfiguration (ex-A05:2021)
    ("/.git/config",        "A02", "Dépôt Git exposé — code source potentiellement accessible", "critique", 9.0),
    ("/backup.zip",         "A02", "Archive de backup accessible publiquement", "critique", 8.0),
    ("/server-status",      "A02", "Page mod_status Apache exposée — informations serveur", "moyen", 5.3),
    ("/robots.txt",         "A02", "robots.txt révèle des chemins sensibles", "faible", 2.5),
    ("/.htaccess",          "A02", ".htaccess accessible directement", "élevé", 6.8),
    ("/web.config",         "A02", "web.config exposé — config IIS en clair", "critique", 8.8),
    ("/swagger-ui.html",    "A02", "API Swagger exposée publiquement sans auth", "moyen", 5.0),
    ("/actuator",           "A02", "Spring Boot Actuator exposé — endpoints sensibles", "élevé", 7.3),
    ("/.DS_Store",          "A02", "Fichier .DS_Store macOS révèle la structure", "moyen", 4.0),
    ("/crossdomain.xml",    "A02", "crossdomain.xml permissif — risque CORS", "moyen", 4.5),
    # A04:2025 Cryptographic Failures (ex-A02:2021)
    ("/.env",               "A04", "Fichier .env exposé — variables d'environnement & secrets", "critique", 9.5),
    ("/config.php",         "A04", "Fichier de configuration PHP exposé — secrets potentiels", "critique", 9.0),
    # A01:2025 Broken Access Control
    ("/admin",              "A01", "Interface admin accessible sans authentification", "élevé", 7.5),
    ("/phpmyadmin",         "A01", "phpMyAdmin exposé publiquement", "critique", 8.5),
    # A07:2025 Authentication Failures
    ("/wp-admin",           "A07", "Interface WordPress admin exposée — brute force possible", "élevé", 7.0),
    # A03:2025 Software Supply Chain Failures (nouveau en 2025)
    ("/package.json",       "A03", "package.json exposé — liste des dépendances npm visible", "moyen", 4.5),
    ("/composer.json",      "A03", "composer.json exposé — dépendances PHP visibles", "moyen", 4.5),
    ("/requirements.txt",   "A03", "requirements.txt exposé — dépendances Python visibles", "moyen", 4.0),
    ("/Gemfile",            "A03", "Gemfile exposé — dépendances Ruby visibles", "moyen", 4.0),
    ("/yarn.lock",          "A03", "yarn.lock exposé — versions exactes des dépendances", "faible", 3.0),
]


class NiktoScanner:
    def __init__(self, target: str):
        self.target = target
        self.use_real = NIKTO_USE_REAL and shutil.which("nikto") is not None

    def run(self) -> list:
        if self.use_real:
            return self._run_real()
        return self._run_simulated()

    # ─── Mode réel ────────────────────────────────────────────────────────
    def _run_real(self) -> list:
        nikto_output = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, prefix="nikto_"
        )
        nikto_output_path = nikto_output.name
        nikto_output.close()

        cmd = [
            "nikto", "-h", self.target,
            "-Format", "csv",
            "-output", nikto_output_path,
            "-Tuning", "123456789abc",
            "-timeout", str(NIKTO_TIMEOUT)
        ]
        try:
            subprocess.run(cmd, timeout=NIKTO_TIMEOUT + 30,
                           capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            pass

        findings = []
        try:
            with open(nikto_output_path) as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) >= 7:
                        findings.append(self._parse_nikto_line(parts))
        except FileNotFoundError:
            pass
        finally:
            try:
                os.unlink(nikto_output_path)
            except Exception:
                pass
        return findings

    def _parse_nikto_line(self, parts: list) -> dict:
        osvdb = parts[4].strip() if len(parts) > 4 else ""
        desc  = parts[6].strip() if len(parts) > 6 else parts[-1].strip()
        uri   = parts[3].strip() if len(parts) > 3 else ""
        return {
            "owasp_id": "A05",
            "nom": f"Nikto — {desc[:60]}",
            "outil": "Nikto",
            "statut": "élevé",
            "technique": f"Nikto scan — OSVDB-{osvdb}",
            "detail": desc,
            "preuve": f"{self.target}{uri}",
            "cvss": 6.5,
            "remediation": "Consultez la base OSVDB et appliquez les patches recommandés.",
            "source": "nikto_real"
        }

    # ─── Mode simulé ──────────────────────────────────────────────────────
    def _run_simulated(self) -> list:
        """
        Envoie de vraies requêtes HTTP pour détecter les fichiers
        et endpoints sensibles listés dans SENSITIVE_PATHS.
        """
        findings = []
        base = self.target.rstrip("/")

        for path, owasp_id, detail, statut, cvss in SENSITIVE_PATHS:
            url = base + path
            try:
                r = requests.get(url, timeout=5, verify=False,
                                 allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    # 403 = fichier existe mais protégé (toujours un finding)
                    effective_statut = statut if r.status_code == 200 else "moyen"
                    effective_cvss = cvss if r.status_code == 200 else cvss * 0.6
                    findings.append({
                        "owasp_id": owasp_id,
                        "nom": f"Ressource sensible : {path}",
                        "outil": "Nikto",
                        "statut": effective_statut,
                        "technique": f"HTTP GET {path} → {r.status_code}",
                        "detail": detail + (
                            " (retourne 403 — ressource présente mais protégée)"
                            if r.status_code == 403 else ""
                        ),
                        "preuve": f"GET {url} → HTTP {r.status_code}",
                        "cvss": round(effective_cvss, 1),
                        "remediation": self._get_remediation(path),
                        "source": "nikto_simulated"
                    })
            except Exception:
                pass

        # Vérification des options HTTP dangereuses (TRACE, PUT, DELETE)
        try:
            r = requests.request("TRACE", base, timeout=5, verify=False)
            if r.status_code < 400:
                findings.append({
                    "owasp_id": "A02",
                    "nom": "Méthode HTTP TRACE activée",
                    "outil": "Nikto",
                    "statut": "élevé",
                    "technique": "HTTP TRACE request",
                    "detail": "La méthode TRACE est activée, permettant des attaques XST (Cross-Site Tracing).",
                    "preuve": f"TRACE {base} → HTTP {r.status_code}",
                    "cvss": 6.4,
                    "remediation": "Désactiver la méthode TRACE dans la configuration du serveur web.",
                    "source": "nikto_simulated"
                })
        except Exception:
            pass

        return findings

    def _get_remediation(self, path: str) -> str:
        remediations = {
            "/.git": "Bloquer l'accès au dossier .git via la configuration serveur web.",
            "/.env": "Ne jamais exposer .env en public. Ajouter à .gitignore et bloquer via nginx/apache.",
            "/admin": "Protéger l'interface admin par authentification forte et restriction IP.",
            "/phpmyadmin": "Désinstaller ou restreindre l'accès à phpMyAdmin à des IPs spécifiques.",
            "/wp-admin": "Activer 2FA sur WordPress et limiter les tentatives de connexion.",
            "/backup": "Stocker les backups hors de la racine web ou dans un bucket privé.",
        }
        for key, rem in remediations.items():
            if key in path:
                return rem
        return "Bloquer l'accès à ce fichier via la configuration du serveur web."
