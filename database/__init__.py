"""
Database module pour OWASP Scanner Pro
"""
from .db import Database

# Instance globale
db = Database()

__all__ = ['db', 'Database']
