"""
Analyseur IA OWASP — utilise l'API Claude pour corréler les findings.
Top 10 OWASP 2025 (publié novembre 2025).

Changements 2021 → 2025 :
  A02 Security Misconfiguration  (#5→#2)
  A03 Software Supply Chain Failures  (nouveau nom, remplace Vulnerable Components)
  A04 Cryptographic Failures  (#2→#4)
  A05 Injection  (#3→#5)
  A06 Insecure Design  (#4→#6)
  A09 Security Logging & Alerting Failures  (renommé, +Alerting)
  A10 Mishandling of Exceptional Conditions  (NOUVEAU — remplace SSRF)
  SSRF absorbé dans A01 Broken Access Control
"""
import json
import requests
from config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL

# ── Top 10 OWASP 2025 — référentiel officiel ──────────────────────────────
OWASP_2025 = {
    "A01": {"name": "Broken Access Control",
            "desc": "IDOR · CORS · Élévation de privilèges · SSRF (absorbé ici en 2025)",
            "sev": "critique", "rank_2021": "A01"},
    "A02": {"name": "Security Misconfiguration",
            "desc": "Configs par défaut · Headers manquants · Services inutiles exposés",
            "sev": "élevé", "rank_2021": "A05"},   # ↑ #5 → #2
    "A03": {"name": "Software Supply Chain Failures",
            "desc": "Dépendances malveillantes · Build pipeline compromis · Paquets npm/pip vérolés",
            "sev": "élevé", "rank_2021": "A06"},   # Nouveau nom
    "A04": {"name": "Cryptographic Failures",
            "desc": "TLS faible · Algo obsolètes · Données sensibles en clair · Clés exposées",
            "sev": "critique", "rank_2021": "A02"}, # ↓ #2 → #4
    "A05": {"name": "Injection",
            "desc": "SQLi · XSS · Commandes OS · LDAP · Template injection · XXE",
            "sev": "critique", "rank_2021": "A03"}, # ↓ #3 → #5
    "A06": {"name": "Insecure Design",
            "desc": "Failles architecturales · Rate limiting absent · Logique métier non sécurisée",
            "sev": "élevé", "rank_2021": "A04"},    # ↓ #4 → #6
    "A07": {"name": "Authentication Failures",
            "desc": "Brute force · Sessions non invalidées · MFA absent · JWT mal configuré",
            "sev": "critique", "rank_2021": "A07"},
    "A08": {"name": "Software or Data Integrity Failures",
            "desc": "Sérialisation non sûre · CI/CD compromis · Mises à jour non vérifiées",
            "sev": "élevé", "rank_2021": "A08"},
    "A09": {"name": "Security Logging and Alerting Failures",
            "desc": "Logs absents · Alertes non configurées · SIEM manquant · Incidents non détectés",
            "sev": "moyen", "rank_2021": "A09"},    # Renommé (+Alerting)
    "A10": {"name": "Mishandling of Exceptional Conditions",
            "desc": "Gestion d'erreurs défaillante · Failing open · Race conditions · Stack traces exposées",
            "sev": "moyen", "rank_2021": None},     # NOUVEAU 2025
}

# Mapping rétro-compatibilité 2021 → 2025
MAPPING_2021_TO_2025 = {
    "A01": "A01", "A02": "A04", "A03": "A05", "A04": "A06",
    "A05": "A02", "A06": "A03", "A07": "A07", "A08": "A08",
    "A09": "A09", "A10": "A01",  # SSRF → A01
}


class OwaspAnalyzer:
    def __init__(self, target: str):
        self.target = target

    def analyze(self, existing_findings: list, owasp_ids: list) -> list:
        existing_findings = self._migrate_findings(existing_findings)
        covered = {f["owasp_id"] for f in existing_findings}
        uncovered = [oid for oid in owasp_ids if oid not in covered]
        
        # Si pas de uncovered, inutile d'appeler l'API
        if not uncovered:
            return []
        
        # Si pas de clé API, fallback direct (évite timeout)
        if not ANTHROPIC_API_KEY or ANTHROPIC_API_KEY == "":
            return self._fallback_analysis(existing_findings, uncovered)
        
        prompt = self._build_prompt(existing_findings, uncovered)
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": ANTHROPIC_MODEL, "max_tokens": 1000,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=15
            )
            data = resp.json()
            raw = "".join(b.get("text", "") for b in data.get("content", []))
            raw = raw.replace("```json", "").replace("```", "").strip()
            return json.loads(raw).get("findings", [])
        except Exception:
            return self._fallback_analysis(existing_findings, uncovered)

    def _migrate_findings(self, findings: list) -> list:
        """Migre automatiquement les owasp_id 2021 → 2025."""
        for f in findings:
            old = f.get("owasp_id", "")
            new = MAPPING_2021_TO_2025.get(old, old)
            if new != old:
                f["owasp_id"] = new
                f["owasp_migration"] = f"{old}:2021 → {new}:2025"
        return findings

    def _build_prompt(self, findings: list, uncovered: list) -> str:
        summary = json.dumps(
            [{"owasp_id": f["owasp_id"], "nom": f["nom"],
              "statut": f["statut"], "detail": f["detail"]}
             for f in findings[:15]], ensure_ascii=False)
        uncovered_desc = ", ".join(
            f"{oid} ({OWASP_2025.get(oid,{}).get('name','')}: "
            f"{OWASP_2025.get(oid,{}).get('desc','')})" for oid in uncovered
        )
        return f"""Tu es un expert sécurité offensive spécialisé OWASP Top 10 **2025**.
Référentiel : OWASP Top 10 2025 (novembre 2025).
Cible analysée : {self.target}

Rappel nomenclature 2025 :
- A02 = Security Misconfiguration (ex-A05:2021)
- A03 = Software Supply Chain Failures (ex-A06:2021, périmètre élargi)
- A10 = Mishandling of Exceptional Conditions (NOUVEAU — gestion erreurs/exceptions)
- SSRF est désormais classifié sous A01 Broken Access Control

Findings détectés par ZAP/Nikto/Burp (déjà migrés en nomenclature 2025) :
{summary}

Vecteurs OWASP 2025 non couverts : {uncovered_desc or "Aucun"}

Mission :
1. Identifier des patterns combinés selon la nomenclature 2025
2. Couvrir A03 (Supply Chain) et A10 (Exceptional Conditions) non testables par scan réseau
3. Classer tout finding SSRF sous A01:2025

Réponds UNIQUEMENT en JSON valide (sans backticks) :
{{
  "findings": [
    {{
      "owasp_id": "<A0X>",
      "owasp_version": "2025",
      "nom": "<nom court>",
      "outil": "Analyse IA",
      "statut": "critique|élevé|moyen|faible|ok",
      "technique": "<méthode>",
      "detail": "<2 phrases>",
      "preuve": "<pattern détecté>",
      "cvss": <0.0-10.0>,
      "remediation": "<action corrective>",
      "source": "ai_correlation_2025"
    }}
  ]
}}
Génère 3 à 6 findings pertinents, sans doublons avec l'existant."""

    def _fallback_analysis(self, existing_findings: list, uncovered: list) -> list:
        """Fallback statique couvrant les vecteurs OWASP 2025 non testables."""
        fallback = []
        if "A10" in uncovered:
            fallback.append({
                "owasp_id": "A10", "owasp_version": "2025",
                "nom": "Gestion des conditions exceptionnelles — nouveau risque A10:2025",
                "outil": "Analyse IA", "statut": "moyen",
                "technique": "Analyse OWASP A10:2025 — Mishandling of Exceptional Conditions",
                "detail": "Nouveau en 2025, A10 couvre les failles de gestion d'erreurs : failing open, stack traces exposées, race conditions. Non détectable par scan réseau.",
                "preuve": "A10:2025 requiert revue manuelle du code et tests d'erreur",
                "cvss": 5.3,
                "remediation": "Auditer la gestion des exceptions, éviter le failing open, ne pas exposer les stack traces en production, gérer les timeouts et états inattendus.",
                "source": "ai_fallback_2025"
            })
        if "A03" in uncovered:
            fallback.append({
                "owasp_id": "A03", "owasp_version": "2025",
                "nom": "Supply Chain — dépendances tierces non auditées",
                "outil": "Analyse IA", "statut": "élevé",
                "technique": "Analyse OWASP A03:2025 — Software Supply Chain Failures",
                "detail": "A03:2025 élargit l'ex-A06 aux paquets malveillants, compromissions de build pipeline et binaires non signés. Non détectable par scan réseau.",
                "preuve": "A03:2025 requiert audit SBOM et pipeline CI/CD",
                "cvss": 7.5,
                "remediation": "Générer un SBOM, activer Dependabot/Snyk, signer les artefacts de build, auditer les accès aux registres npm/pip.",
                "source": "ai_fallback_2025"
            })
        if "A09" in uncovered:
            fallback.append({
                "owasp_id": "A09", "owasp_version": "2025",
                "nom": "Logging & Alerting insuffisants (A09:2025)",
                "outil": "Analyse IA", "statut": "moyen",
                "technique": "Analyse OWASP A09:2025",
                "detail": "A09:2025 insiste sur l'alerting en plus du logging. Logs sans alertes = incidents non détectés. Non vérifiable par scan réseau.",
                "preuve": "A09:2025 nécessite audit SIEM et tests de détection",
                "cvss": 4.0,
                "remediation": "Configurer un SIEM (ELK/Splunk) avec alertes temps réel. Tester la détection avec des simulations d'attaques.",
                "source": "ai_fallback_2025"
            })
        if "A06" in uncovered:
            fallback.append({
                "owasp_id": "A06", "owasp_version": "2025",
                "nom": "Insecure Design — revue architecturale recommandée",
                "outil": "Analyse IA", "statut": "élevé",
                "technique": "Threat modeling A06:2025",
                "detail": "Failles de conception non détectables par scan : rate limiting absent, logique métier incorrecte, flux d'auth non sécurisé par design.",
                "preuve": "A06:2025 requiert threat modeling manuel",
                "cvss": 6.0,
                "remediation": "Effectuer un threat modeling STRIDE/PASTA. Implémenter le rate limiting. Revoir les flux d'authentification.",
                "source": "ai_fallback_2025"
            })
        return fallback
