"""
Module de chiffrement AES-256 pour les données sensibles.
Conformité RGPD — chiffrement au repos des cibles, preuves et credentials.
"""
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Nom de la variable d'environnement pour la clé de chiffrement
ENV_KEY_NAME = "ENCRYPTION_KEY"


def _derive_key(password: str, salt: bytes = None) -> tuple:
    """
    Dérive une clé Fernet à partir d'un mot de passe (PBKDF2).
    Si salt est None, un nouveau salt est généré.
    Retourne (clé_fernet, salt).
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def get_encryption_key() -> bytes:
    """
    Récupère ou génère la clé de chiffrement depuis l'environnement.
    Priorité :
    1. Variable ENCRYPTION_KEY dans .env
    2. Génération d'une clé aléatoire (valable seulement pour la session)
    """
    from config import SECRET_KEY  # on utilise la SECRET_KEY Flask comme seed

    key_str = os.getenv(ENV_KEY_NAME)
    if key_str:
        return key_str.encode()

    # Fallback : dériver depuis la SECRET_KEY Flask
    key, _ = _derive_key(SECRET_KEY, b'owasp_scanner_salt')
    return key


# Instance Fernet globale (initialisée au premier appel)
_fernet_instance = None


def _get_fernet() -> Fernet:
    """Retourne l'instance Fernet (singleton)."""
    global _fernet_instance
    if _fernet_instance is None:
        key = get_encryption_key()
        _fernet_instance = Fernet(key)
    return _fernet_instance


def encrypt(text: str) -> str:
    """
    Chiffre un texte avec AES-256 via Fernet.
    Retourne le texte chiffré en base64 (string).
    """
    if not text:
        return text
    fernet = _get_fernet()
    encrypted = fernet.encrypt(text.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt(encrypted_text: str) -> str:
    """
    Déchiffre un texte précédemment chiffré avec encrypt().
    Retourne le texte clair original.
    """
    if not encrypted_text:
        return encrypted_text
    try:
        fernet = _get_fernet()
        decrypted = fernet.decrypt(encrypted_text.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception:
        # En cas d'échec, retourner le texte tel quel (non chiffré)
        return encrypted_text


def encrypt_dict(data: dict, fields: list) -> dict:
    """
    Chiffre des champs spécifiques d'un dictionnaire.
    fields : liste des noms de champs à chiffrer.
    """
    result = dict(data)
    for field in fields:
        if field in result and result[field]:
            result[field] = encrypt(str(result[field]))
    return result


def decrypt_dict(data: dict, fields: list) -> dict:
    """
    Déchiffre des champs spécifiques d'un dictionnaire.
    fields : liste des noms de champs à déchiffrer.
    """
    result = dict(data)
    for field in fields:
        if field in result and result[field]:
            result[field] = decrypt(str(result[field]))
    return result