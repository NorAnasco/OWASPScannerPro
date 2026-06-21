"""
Rate Limiter — anti-brute-force et protection des endpoints sensibles.
Utilise un cache mémoire avec timestamp + compteur par IP.
"""
import time
import threading
from functools import wraps
from flask import request, jsonify


class RateLimiter:
    """
    Rate limiter simple basé sur une fenêtre glissante (sliding window).
    
    Usage:
        limiter = RateLimiter()
        
        @app.route('/login', methods=['POST'])
        @limiter.limit(max_attempts=5, window=60)  # 5 tentatives par minute
        def login():
            ...
    """
    
    def __init__(self):
        self._attempts = {}  # {ip: [(timestamp,), ...]}
        self._lock = threading.Lock()
    
    def _cleanup(self, ip: str, window: int):
        """Supprime les tentatives plus vieilles que window secondes."""
        now = time.time()
        if ip in self._attempts:
            self._attempts[ip] = [
                ts for ts in self._attempts[ip]
                if now - ts < window
            ]
            if not self._attempts[ip]:
                del self._attempts[ip]
    
    def is_limited(self, ip: str, max_attempts: int = 5, window: int = 60) -> bool:
        """
        Vérifie si une IP a dépassé le nombre max de tentatives.
        Retourne True si l'IP est bloquée (rate limited).
        """
        with self._lock:
            self._cleanup(ip, window)
            attempts = self._attempts.get(ip, [])
            return len(attempts) >= max_attempts
    
    def record_attempt(self, ip: str):
        """Enregistre une tentative pour une IP."""
        with self._lock:
            if ip not in self._attempts:
                self._attempts[ip] = []
            self._attempts[ip].append(time.time())
    
    def reset(self, ip: str):
        """Réinitialise le compteur pour une IP (ex: après login réussi)."""
        with self._lock:
            self._attempts.pop(ip, None)
    
    def get_remaining(self, ip: str, max_attempts: int = 5, window: int = 60) -> int:
        """Retourne le nombre de tentatives restantes avant blocage."""
        with self._lock:
            self._cleanup(ip, window)
            attempts = self._attempts.get(ip, [])
            return max(0, max_attempts - len(attempts))
    
    def limit(self, max_attempts: int = 5, window: int = 60,
              error_message: str = "Trop de tentatives. Veuillez réessayer dans {window} secondes."):
        """
        Décorateur pour limiter le taux de requêtes sur une route.
        
        Args:
            max_attempts: Nombre maximum de tentatives autorisées
            window: Fenêtre de temps en secondes
            error_message: Message d'erreur (peut contenir {window})
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                ip = request.remote_addr or '0.0.0.0'
                
                if self.is_limited(ip, max_attempts, window):
                    remaining = self.get_remaining(ip, max_attempts, window)
                    retry_after = window
                    
                    resp = jsonify({
                        'error': error_message.format(window=window),
                        'retry_after': retry_after,
                        'remaining_attempts': remaining
                    })
                    resp.status_code = 429  # Too Many Requests
                    resp.headers['Retry-After'] = str(retry_after)
                    resp.headers['X-RateLimit-Remaining'] = str(remaining)
                    resp.headers['X-RateLimit-Limit'] = str(max_attempts)
                    return resp
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator


# Instance globale pour l'application
login_limiter = RateLimiter()
api_limiter = RateLimiter()