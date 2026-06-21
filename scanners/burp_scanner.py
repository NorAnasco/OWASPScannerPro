"""
Scanner Burp Suite — utilise l'API REST de Burp Suite Pro (port 1337).
Nécessite : Burp Suite Pro avec l'extension REST API activée.
En mode simulé : tests d'injection réels via requests.
"""
import requests
import time
import json
from typing import Optional
from config import BURP_HOST, BURP_PORT, BURP_API_KEY, BURP_USE_REAL


# Payloads de test XSS
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
]

# Payloads SQLi basiques (détection seulement — pas d'exploitation)
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "1; DROP TABLE--",
    "' UNION SELECT NULL--",
]

# Indicateurs d'erreur SQL dans la réponse
SQL_ERRORS = [
    "you have an error in your sql",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "ORA-",
    "pg_query",
    "sqlite_",
    "microsoft ole db",
]


class BurpScanner:
    def __init__(self, target: str):
        self.target = target
        self.use_real = BURP_USE_REAL

    def run(self, owasp_ids: list) -> list:
        if self.use_real:
            return self._run_real(owasp_ids)
        return self._run_simulated(owasp_ids)

    # ─── Mode réel (Burp Suite Pro REST API) ──────────────────────────────
    def _run_real(self, owasp_ids: list) -> list:
        base_url = f"http://{BURP_HOST}:{BURP_PORT}/v0.1"
        headers = {"Authorization": f"Bearer {BURP_API_KEY}",
                   "Content-Type": "application/json"}

        # Créer une tâche de scan
        payload = {"urls": [self.target], "scan_configurations": [
            {"name": "Crawl and Audit - Thorough"}
        ]}
        r = requests.post(f"{base_url}/scan", headers=headers,
                          json=payload, timeout=10)
        scan_id = r.headers.get("Location", "").split("/")[-1]

        # Attendre la fin du scan
        for _ in range(60):
            status = requests.get(f"{base_url}/scan/{scan_id}",
                                  headers=headers, timeout=10).json()
            if status.get("scan_status") == "succeeded":
                break
            time.sleep(10)

        # Récupérer les issues
        issues = requests.get(f"{base_url}/scan/{scan_id}/issue_events",
                              headers=headers, timeout=10).json()
        return [self._issue_to_finding(i["issue"]) for i in issues
                if "issue" in i]

    def _issue_to_finding(self, issue: dict) -> dict:
        sev_map = {"high": "critique", "medium": "élevé",
                   "low": "moyen", "info": "faible"}
        return {
            "owasp_id": "A05",
            "nom": issue.get("name", "Issue Burp"),
            "outil": "Burp Suite",
            "statut": sev_map.get(issue.get("severity", "low"), "moyen"),
            "technique": "Burp Active Scan",
            "detail": issue.get("description", ""),
            "preuve": issue.get("evidence", [{}])[0].get("request_response",
                      {}).get("request", "") if issue.get("evidence") else "",
            "cvss": {"high": 8.0, "medium": 5.5, "low": 3.0,
                     "info": 1.0}.get(issue.get("severity", "low"), 3.0),
            "remediation": issue.get("remediation", "Consulter la doc Burp Suite."),
            "source": "burp_real"
        }

    # ─── Mode simulé ──────────────────────────────────────────────────────
    def _run_simulated(self, owasp_ids: list) -> list:
        """Tests d'injection actifs — XSS réfléchi, SQLi, open redirect, CSRF."""
        findings = []
        session = requests.Session()
        session.verify = False

        # Récupérer les formulaires et paramètres de la page principale
        try:
            resp = session.get(self.target, timeout=8)
        except Exception:
            return []

        # Test XSS réfléchi dans les paramètres d'URL
        if "A05" in owasp_ids:  # A05:2025 Injection (ex-A03:2021)
            xss_finding = self._test_xss(session, resp.url)
            if xss_finding:
                findings.append(xss_finding)

        # Test SQLi sur les paramètres d'URL
        if "A05" in owasp_ids:  # A05:2025 Injection (ex-A03:2021)
            sqli_finding = self._test_sqli(session, resp.url)
            if sqli_finding:
                findings.append(sqli_finding)

        # Test Open Redirect
        if "A01" in owasp_ids:
            redirect_finding = self._test_open_redirect(session)
            if redirect_finding:
                findings.append(redirect_finding)

        # Test CSRF (absence de token)
        if "A01" in owasp_ids or "A07" in owasp_ids:
            csrf_finding = self._test_csrf(session, resp)
            if csrf_finding:
                findings.append(csrf_finding)

        # Test Directory Traversal
        if "A01" in owasp_ids:
            traversal = self._test_directory_traversal(session)
            if traversal:
                findings.append(traversal)

        # Test méthodes HTTP non restreintes
        if "A02" in owasp_ids:  # A02:2025 Security Misconfiguration (ex-A05:2021)
            method_finding = self._test_http_methods(session)
            if method_finding:
                findings.append(method_finding)

        return findings

    def _test_xss(self, session, url: str) -> Optional[dict]:
        """Injecte des payloads XSS dans les paramètres connus."""
        test_params = ["q", "search", "query", "id", "name", "input", "s"]
        base = url.split("?")[0]

        for param in test_params:
            for payload in XSS_PAYLOADS[:2]:  # limiter les requêtes
                try:
                    r = session.get(base, params={param: payload}, timeout=5)
                    if payload in r.text:
                        return {
                            "owasp_id": "A05",  # A05:2025 Injection
                            "nom": "XSS réfléchi détecté",
                            "outil": "Burp Suite",
                            "statut": "critique",
                            "technique": f"Injection XSS dans le paramètre ?{param}=",
                            "detail": f"Le paramètre '{param}' réfléchit le payload XSS sans encodage.",
                            "preuve": f"GET {base}?{param}={payload} → payload présent dans la réponse",
                            "cvss": 8.8,
                            "remediation": "Encoder toutes les sorties utilisateur. Implémenter une CSP stricte.",
                            "source": "burp_simulated"
                        }
                except Exception:
                    pass
        return None

    def _test_sqli(self, session, url: str) -> Optional[dict]:
        """Injecte des payloads SQLi basiques."""
        test_params = ["id", "user", "item", "product", "category", "page"]
        base = url.split("?")[0]

        for param in test_params:
            for payload in SQLI_PAYLOADS[:2]:
                try:
                    r = session.get(base, params={param: payload}, timeout=5)
                    body = r.text.lower()
                    for error in SQL_ERRORS:
                        if error in body:
                            return {
                                "owasp_id": "A05",  # A05:2025 Injection
                                "nom": "Injection SQL détectée",
                                "outil": "Burp Suite",
                                "statut": "critique",
                                "technique": f"SQLi sur le paramètre ?{param}= (error-based)",
                                "detail": f"Erreur SQL exposée en réponse au payload injecté dans '{param}'.",
                                "preuve": f"GET {base}?{param}={payload} → erreur SQL dans la réponse",
                                "cvss": 9.8,
                                "remediation": "Utiliser des requêtes préparées (prepared statements) et un ORM. Ne jamais exposer les erreurs SQL.",
                                "source": "burp_simulated"
                            }
                except Exception:
                    pass
        return None

    def _test_open_redirect(self, session) -> Optional[dict]:
        redirects = ["next", "redirect", "url", "return", "goto", "destination"]
        base = self.target.rstrip("/")
        for param in redirects:
            try:
                r = session.get(base, params={param: "https://evil.com"},
                                timeout=5, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if "evil.com" in loc:
                    return {
                        "owasp_id": "A01",
                        "nom": "Open Redirect détecté",
                        "outil": "Burp Suite",
                        "statut": "élevé",
                        "technique": f"Open redirect via ?{param}=",
                        "detail": f"Le paramètre '{param}' permet une redirection vers un domaine externe arbitraire.",
                        "preuve": f"GET ?{param}=https://evil.com → Location: {loc}",
                        "cvss": 7.4,
                        "remediation": "Valider et whitelister les URLs de redirection. Refuser les URLs externes.",
                        "source": "burp_simulated"
                    }
            except Exception:
                pass
        return None

    def _test_csrf(self, session, resp) -> Optional[dict]:
        """Vérifie la présence de tokens CSRF dans les formulaires HTML."""
        from html.parser import HTMLParser

        class FormParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []
                self.current_form = None
                self.csrf_found = False

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form" and attrs.get("method", "get").lower() == "post":
                    self.current_form = attrs
                if tag == "input":
                    name = attrs.get("name", "").lower()
                    if any(k in name for k in ["csrf", "token", "_token", "nonce"]):
                        self.csrf_found = True

        parser = FormParser()
        try:
            parser.feed(resp.text)
            if parser.current_form and not parser.csrf_found:
                return {
                    "owasp_id": "A01",
                    "nom": "Formulaire POST sans protection CSRF",
                    "outil": "Burp Suite",
                    "statut": "élevé",
                    "technique": "Analyse des formulaires HTML",
                    "detail": "Un formulaire POST a été détecté sans token CSRF, exposant les utilisateurs aux attaques CSRF.",
                    "preuve": f"<form method='post' action='{parser.current_form.get('action', '')}'>  — aucun champ csrf trouvé",
                    "cvss": 7.1,
                    "remediation": "Implémenter des tokens CSRF synchronisés sur tous les formulaires POST (SameSite=Strict sur les cookies).",
                    "source": "burp_simulated"
                }
        except Exception:
            pass
        return None

    def _test_directory_traversal(self, session) -> Optional[dict]:
        payloads = [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd"
        ]
        params = ["file", "path", "doc", "page", "include", "template"]
        base = self.target.rstrip("/")
        for param in params:
            for payload in payloads[:1]:
                try:
                    r = session.get(base, params={param: payload}, timeout=5)
                    if "root:" in r.text or "daemon:" in r.text:
                        return {
                            "owasp_id": "A01",
                            "nom": "Path Traversal (LFI) détecté",
                            "outil": "Burp Suite",
                            "statut": "critique",
                            "technique": f"Directory traversal via ?{param}=",
                            "detail": "Le serveur permet la lecture de fichiers système via traversée de répertoires.",
                            "preuve": f"GET ?{param}={payload} → contenu /etc/passwd lisible",
                            "cvss": 9.1,
                            "remediation": "Valider et canonicaliser tous les chemins de fichiers. Utiliser une liste blanche.",
                            "source": "burp_simulated"
                        }
                except Exception:
                    pass
        return None

    def _test_http_methods(self, session) -> Optional[dict]:
        try:
            r = session.options(self.target, timeout=5)
            allow = r.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "PATCH", "CONNECT"]
                         if m in allow]
            if dangerous:
                return {
                    "owasp_id": "A05",
                    "nom": f"Méthodes HTTP dangereuses activées : {', '.join(dangerous)}",
                    "outil": "Burp Suite",
                    "statut": "élevé",
                    "technique": "HTTP OPTIONS request",
                    "detail": f"Le serveur autorise les méthodes {', '.join(dangerous)} qui peuvent permettre la modification de ressources.",
                    "preuve": f"OPTIONS {self.target} → Allow: {allow}",
                    "cvss": 6.5,
                    "remediation": "Restreindre les méthodes HTTP autorisées à GET et POST uniquement dans la configuration serveur.",
                    "source": "burp_simulated"
                }
        except Exception:
            pass
        return None
