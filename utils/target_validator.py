"""
Valide et sécurise les cibles avant scan.
Bloque les IPs privées et les URLs malformées.
"""
import re
import ipaddress
import socket
from urllib.parse import urlparse


# Plages d'IPs privées / réservées — ne jamais scanner sans autorisation
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Domaines de test autorisés (whitelist — modifier selon vos besoins)
ALLOWED_TEST_DOMAINS = {
    "testphp.vulnweb.com",       # OWASP test site (Acunetix)
    "juice-shop.herokuapp.com",  # OWASP Juice Shop
    "dvwa.co.uk",
    "hackthissite.org",
    "webscantest.com",
    "demo.testfire.net",
}


def validate_target(url: str) -> tuple[bool, str]:
    """
    Retourne (True, "") si l'URL est valide et scannable,
    ou (False, "message d'erreur") sinon.
    """
    if not url:
        return False, "URL cible requise."

    # Ajouter le schéma si absent
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "URL malformée."

    if parsed.scheme not in ("http", "https"):
        return False, "Seuls les schémas http et https sont autorisés."

    hostname = parsed.hostname
    if not hostname:
        return False, "Nom d'hôte manquant dans l'URL."

    # Bloquer les IP privées (SSRF protection)
    try:
        ip = ipaddress.ip_address(hostname)
        for private_range in PRIVATE_RANGES:
            if ip in private_range:
                return False, f"Les adresses IP privées/locales ne sont pas autorisées ({hostname})."
    except ValueError:
        # C'est un nom de domaine, pas une IP — résoudre pour vérifier
        try:
            resolved_ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            for private_range in PRIVATE_RANGES:
                if resolved_ip in private_range:
                    return False, f"Le domaine résout vers une IP privée ({resolved_ip}). Scan refusé."
        except (socket.gaierror, socket.herror):
            return False, f"Impossible de résoudre le domaine : {hostname}"

    # Vérification basique du format de domaine
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    if not domain_pattern.match(hostname) and not _is_valid_ip(hostname):
        return False, f"Nom de domaine invalide : {hostname}"

    return True, ""


def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
