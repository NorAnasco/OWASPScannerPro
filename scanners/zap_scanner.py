"""
Scanner OWASP ZAP — utilise l'API REST de ZAP (zapv2).
Nécessite : pip install python-owasp-zap-v2.4 requests
ZAP doit tourner en mode daemon : zap.sh -daemon -port 8080 -host 127.0.0.1
"""
import time
import requests
from zapv2 import ZAPv2
from config import ZAP_HOST, ZAP_PORT, ZAP_API_KEY, ZAP_USE_REAL


# Mapping ZAP alert risk → statut interne
RISK_MAP = {
    "High": "critique",
    "Medium": "élevé",
    "Low": "moyen",
    "Informational": "faible"
}

# Mapping CWE → OWASP Top 10 2025
# Sources : https://owasp.org/Top10/2025/
CWE_TO_OWASP = {
    # A01:2025 — Broken Access Control (inclut SSRF depuis 2025)
    "284": "A01", "285": "A01", "352": "A01",
    "425": "A01", "918": "A01",               # SSRF → A01 en 2025 (ex-A10:2021)
    # A02:2025 — Security Misconfiguration (ex-A05:2021)
    "16": "A02", "611": "A02", "693": "A02",
    "732": "A02", "1004": "A02",
    # A03:2025 — Software Supply Chain Failures (ex-A06:2021)
    "494": "A03", "829": "A03", "1104": "A03",
    # A04:2025 — Cryptographic Failures (ex-A02:2021)
    "200": "A04", "311": "A04", "326": "A04",
    "327": "A04", "328": "A04",
    # A05:2025 — Injection (ex-A03:2021)
    "79": "A05", "89": "A05", "78": "A05",
    "91": "A05", "601": "A05",
    # A07:2025 — Authentication Failures
    "287": "A07", "306": "A07", "307": "A07",
    "384": "A07", "521": "A07",
    # A08:2025 — Software or Data Integrity Failures
    "345": "A08", "346": "A08", "502": "A08",
}

# Timeouts (secondes)
SPIDER_TIMEOUT = 300
PASSIVE_SCAN_TIMEOUT = 120
ACTIVE_SCAN_TIMEOUT = 900
POLL_INTERVAL = 2


class ZapScanner:
    def __init__(self, target: str):
        self.target = target
        self.use_real = ZAP_USE_REAL and self._is_zap_running()

    # ─── Détection du daemon ────────────────────────────────────────────
    def _is_zap_running(self) -> bool:
        """
        Vérifie que le daemon ZAP répond réellement sur ZAP_HOST:ZAP_PORT,
        plutôt que de simplement vérifier la présence du binaire zap.sh.
        """
        try:
            # Ping rapide sur le port avant d'instancier ZAPv2 (qui n'a pas
            # de timeout court configurable facilement)
            requests.get(f"http://{ZAP_HOST}:{ZAP_PORT}", timeout=2)
        except requests.exceptions.RequestException:
            return False

        try:
            zap = ZAPv2(
                apikey=ZAP_API_KEY,
                proxies={"http": f"http://{ZAP_HOST}:{ZAP_PORT}",
                         "https": f"http://{ZAP_HOST}:{ZAP_PORT}"}
            )
            _ = zap.core.version  # lève une exception si l'API ne répond pas correctement
            return True
        except Exception:
            return False

    def run(self, owasp_ids: list) -> list:
        if self.use_real:
            try:
                return self._run_real(owasp_ids)
            except Exception as e:
                print(f"[ZapScanner] Échec du mode réel ({e}), fallback en mode simulé")
                return self._run_simulated(owasp_ids)
        return self._run_simulated(owasp_ids)

    # ─── Mode réel ────────────────────────────────────────────────────────
    def _run_real(self, owasp_ids: list) -> list:
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={"http": f"http://{ZAP_HOST}:{ZAP_PORT}",
                     "https": f"http://{ZAP_HOST}:{ZAP_PORT}"}
        )

        # Spider, restreint au sous-arbre de la cible pour ne pas suivre
        # les liens externes hors scope
        spider_id = zap.spider.scan(
            self.target, contextname=None, subtreeonly=True, apikey=ZAP_API_KEY
        )
        self._poll(lambda: zap.spider.status(spider_id), SPIDER_TIMEOUT, "spider")

        # Scan passif — attendre que la file de records à analyser soit vide,
        # plutôt qu'un sleep arbitraire
        self._poll(
            lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0,
            PASSIVE_SCAN_TIMEOUT, "passive scan"
        )

        # Scan actif
        ascan_id = zap.ascan.scan(self.target, apikey=ZAP_API_KEY)
        self._poll(lambda: zap.ascan.status(ascan_id), ACTIVE_SCAN_TIMEOUT, "active scan")

        alerts = zap.core.alerts(baseurl=self.target)
        return [self._alert_to_finding(a) for a in alerts]

    def _poll(self, status_fn, timeout: int, label: str):
        """Poll une fonction de statut ZAP (0-100) jusqu'à complétion ou timeout."""
        start = time.time()
        while int(status_fn()) < 100:
            if time.time() - start > timeout:
                raise TimeoutError(f"Timeout ZAP dépassé pendant : {label}")
            time.sleep(POLL_INTERVAL)

    def _alert_to_finding(self, alert: dict) -> dict:
        cwe = str(alert.get("cweid", ""))
        owasp_id = CWE_TO_OWASP.get(cwe)
        if owasp_id is None:
            owasp_id = "non-classé"
            print(f"[ZapScanner] CWE-{cwe} non mappé vers un ID OWASP — à ajouter au mapping")
        return {
            "owasp_id": owasp_id,
            "nom": alert.get("name", "Alerte ZAP"),
            "outil": "OWASP ZAP",
            "statut": RISK_MAP.get(alert.get("riskdesc", "Low").split(" ")[0], "moyen"),
            "technique": f"ZAP Active Scan — CWE-{cwe}",
            "detail": alert.get("desc", ""),
            "preuve": alert.get("evidence", alert.get("url", "")),
            "cvss": self._risk_to_cvss(alert.get("riskdesc", "Low")),
            "remediation": alert.get("solution", "Consulter la documentation ZAP"),
            "source": "zap_real"
        }

    def _risk_to_cvss(self, risk: str) -> float:
        return {"High": 8.5, "Medium": 5.5, "Low": 3.0, "Informational": 1.0}.get(
            risk.split(" ")[0], 3.0)

    # ─── Mode simulé (ZAP non installé / non joignable) ───────────────────
    def _run_simulated(self, owasp_ids: list) -> list:
        """
        Effectue de vraies requêtes HTTP sur la cible et analyse
        les réponses pour détecter des indicateurs de vulnérabilités.
        """
        findings = []
        headers_to_check = {
            # A02:2025 Security Misconfiguration (ex-A05:2021)
            "X-Frame-Options": ("A02", "Clickjacking possible — header X-Frame-Options absent", "élevé", 6.1),
            "X-Content-Type-Options": ("A02", "MIME sniffing possible — header X-Content-Type-Options absent", "moyen", 4.3),
            "Permissions-Policy": ("A02", "Permissions-Policy absent — accès caméra/micro non restreint", "faible", 2.0),
            # A04:2025 Cryptographic Failures (ex-A02:2021)
            "Strict-Transport-Security": ("A04", "HSTS absent — connexion HTTP non forcée vers HTTPS", "élevé", 6.5),
            "Referrer-Policy": ("A04", "Fuite d'informations via Referer header", "faible", 2.5),
            # A05:2025 Injection (ex-A03:2021) — XSS mitigations
            "Content-Security-Policy": ("A05", "CSP absent — vecteur XSS non atténué", "élevé", 7.2),
            "X-XSS-Protection": ("A05", "Protection XSS navigateur non activée", "moyen", 4.0),
        }
        try:
            # verify=True (implicite) pour que la détection SSLError ci-dessous
            # ait un sens — verify=False annulerait l'exception
            resp = requests.get(self.target, timeout=10, allow_redirects=True)

            # Headers manquants
            for header, (owasp_id, detail, statut, cvss) in headers_to_check.items():
                if owasp_id in owasp_ids and header not in resp.headers:
                    findings.append({
                        "owasp_id": owasp_id,
                        "nom": f"Header {header} manquant",
                        "outil": "OWASP ZAP",
                        "statut": statut,
                        "technique": "Analyse passive des en-têtes HTTP",
                        "detail": detail,
                        "preuve": f"GET {self.target} → {header}: (absent)",
                        "cvss": cvss,
                        "remediation": f"Ajouter le header {header} dans la configuration du serveur web.",
                        "source": "zap_passive"
                    })

            # TLS / HTTPS
            if "A04" in owasp_ids and self.target.startswith("http://"):
                findings.append({
                    "owasp_id": "A04",
                    "nom": "HTTP non chiffré détecté",
                    "outil": "OWASP ZAP",
                    "statut": "critique",
                    "technique": "Détection du schéma de protocole",
                    "detail": "La cible utilise HTTP non chiffré. Les données transitent en clair.",
                    "preuve": self.target,
                    "cvss": 8.1,
                    "remediation": "Rediriger tout le trafic HTTP vers HTTPS. Activer TLS 1.2+.",
                    "source": "zap_passive"
                })

            # Version serveur exposée — corrigé : filtre et classification cohérents (A02)
            if "A02" in owasp_ids:
                server = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                if server or powered:
                    findings.append({
                        "owasp_id": "A02",
                        "nom": "Version serveur exposée",
                        "outil": "OWASP ZAP",
                        "statut": "moyen",
                        "technique": "Analyse des en-têtes de réponse",
                        "detail": "Le serveur révèle sa version dans les en-têtes HTTP, facilitant le ciblage de CVE.",
                        "preuve": f"Server: {server or powered}",
                        "cvss": 4.3,
                        "remediation": "Masquer les en-têtes Server et X-Powered-By dans la config serveur.",
                        "source": "zap_passive"
                    })

            # Cookie flags
            if "A07" in owasp_ids:
                for cookie in resp.cookies:
                    issues = []
                    if not cookie.secure:
                        issues.append("Secure flag absent")

                    cookie_rest = getattr(cookie, '_rest', {})
                    httponly_present = any("httponly" in k.lower() for k in cookie_rest.keys())
                    if not httponly_present:
                        issues.append("HttpOnly flag absent")

                    samesite_present = any("samesite" in k.lower() for k in cookie_rest.keys())
                    if not samesite_present:
                        issues.append("SameSite non défini")

                    if issues:
                        findings.append({
                            "owasp_id": "A07",
                            "nom": f"Cookie non sécurisé : {cookie.name}",
                            "outil": "OWASP ZAP",
                            "statut": "élevé",
                            "technique": "Inspection des attributs de cookies",
                            "detail": f"Cookie '{cookie.name}' manque : {', '.join(issues)}.",
                            "preuve": f"Set-Cookie: {cookie.name}=... ({', '.join(issues)})",
                            "cvss": 6.3,
                            "remediation": "Définir les flags Secure, HttpOnly et SameSite=Strict sur tous les cookies de session.",
                            "source": "zap_passive"
                        })

        except requests.exceptions.SSLError:
            if "A04" in owasp_ids:
                findings.append({
                    "owasp_id": "A04",
                    "nom": "Erreur certificat TLS",
                    "outil": "OWASP ZAP",
                    "statut": "critique",
                    "technique": "Handshake TLS",
                    "detail": "Le certificat SSL/TLS est invalide, expiré ou auto-signé.",
                    "preuve": f"SSLError sur {self.target}",
                    "cvss": 7.5,
                    "remediation": "Renouveler le certificat via Let's Encrypt ou une CA reconnue.",
                    "source": "zap_passive"
                })
        except requests.exceptions.RequestException as e:
            print(f"[ZapScanner] Erreur réseau pendant le scan simulé : {e}")

        return findings