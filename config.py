"""
Configuration centrale du moteur OWASP Scanner.
Chargez vos vraies valeurs via variables d'environnement (.env).
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Anthropic / Claude ────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

# ── OWASP ZAP ────────────────────────────────────────────────────────────────
# ZAP doit tourner en daemon : zap.sh -daemon -port 8080 -host 127.0.0.1
ZAP_HOST    = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT    = int(os.getenv("ZAP_PORT", "8080"))
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "changeme")
# Mettre à True si ZAP est installé et démarré
ZAP_USE_REAL = os.getenv("ZAP_USE_REAL", "false").lower() == "true"

# ── Nikto ─────────────────────────────────────────────────────────────────────
NIKTO_USE_REAL  = os.getenv("NIKTO_USE_REAL", "false").lower() == "true"
NIKTO_TIMEOUT   = int(os.getenv("NIKTO_TIMEOUT", "120"))  # secondes

# ── Burp Suite Pro REST API ───────────────────────────────────────────────────
# Burp Suite Pro doit tourner avec l'extension REST API activée (port 1337)
BURP_HOST    = os.getenv("BURP_HOST", "127.0.0.1")
BURP_PORT    = int(os.getenv("BURP_PORT", "1337"))
BURP_API_KEY = os.getenv("BURP_API_KEY", "")
BURP_USE_REAL = os.getenv("BURP_USE_REAL", "false").lower() == "true"

# ── Nmap ──────────────────────────────────────────────────────────────────────
# Nmap doit être installé : sudo apt install nmap (ou brew install nmap sur Mac)
NMAP_USE_REAL = os.getenv("NMAP_USE_REAL", "false").lower() == "true"

# ── Flask ─────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-in-production")
DEBUG      = os.getenv("DEBUG", "true").lower() == "true"
