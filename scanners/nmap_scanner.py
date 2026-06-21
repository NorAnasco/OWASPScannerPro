"""
Scanner Nmap — cartographie réseau et détection de ports ouverts.
Nmap doit être installé : sudo apt install nmap (ou brew install nmap sur Mac)

En mode réel : exécute nmap en sous-processus pour détecter les ports ouverts et protocoles.
En mode simulé : effectue des tentatives de connexion TCP/UDP sur les ports courants.
"""
import subprocess
import shutil
import socket
import json
from config import NMAP_USE_REAL


# Ports courants à tester en mode simulé
# Format : (port, protocole, service, owasp_id, risque)
COMMON_PORTS = [
    # Services web
    (80, "tcp", "HTTP", "A04", "moyen", 4.3),
    (8080, "tcp", "HTTP Alternative", "A04", "moyen", 4.3),
    (443, "tcp", "HTTPS", "A04", "faible", 2.0),
    (8443, "tcp", "HTTPS Alternative", "A04", "faible", 2.0),
    
    # SSH / Accès à distance
    (22, "tcp", "SSH", "A01", "élevé", 7.5),
    (2222, "tcp", "SSH Alternatif", "A01", "élevé", 7.5),
    
    # Bases de données
    (3306, "tcp", "MySQL", "A04", "critique", 9.0),
    (5432, "tcp", "PostgreSQL", "A04", "critique", 9.0),
    (1433, "tcp", "MSSQL", "A04", "critique", 9.0),
    (27017, "tcp", "MongoDB", "A04", "critique", 9.1),
    (6379, "tcp", "Redis", "A04", "critique", 8.8),
    
    # Services d'administration
    (3389, "tcp", "RDP", "A01", "critique", 8.5),
    (5900, "tcp", "VNC", "A01", "critique", 8.3),
    
    # Mail & DNS
    (25, "tcp", "SMTP", "A02", "moyen", 5.0),
    (53, "tcp", "DNS", "A02", "moyen", 4.5),
    (53, "udp", "DNS UDP", "A02", "moyen", 4.5),
    (110, "tcp", "POP3", "A04", "élevé", 6.5),
    (143, "tcp", "IMAP", "A04", "élevé", 6.5),
    
    # Services d'application
    (8000, "tcp", "App Server", "A02", "moyen", 4.5),
    (8888, "tcp", "Alt App Server", "A02", "moyen", 4.5),
    (9000, "tcp", "Autre service", "A02", "moyen", 4.0),
    
    # FTP
    (21, "tcp", "FTP", "A01", "critique", 8.1),
    (2121, "tcp", "FTP Alt", "A01", "critique", 8.1),
    
    # Services de cache/queue
    (5671, "tcp", "AMQP", "A02", "moyen", 5.0),
    (5672, "tcp", "AMQP Alt", "A02", "moyen", 5.0),
]

# Mapping port → détail de risque
PORT_RISK_DETAILS = {
    22: "SSH exposé — risque de brute force et accès non autorisé",
    3306: "MySQL non chiffré — données transitent en clair, accès à la DB possible",
    5432: "PostgreSQL exposé — accès direct à la base de données",
    1433: "MSSQL exposé — accès à Microsoft SQL Server possible",
    27017: "MongoDB non sécurisé — pas d'authentification par défaut",
    6379: "Redis non sécurisé — données en mémoire accessibles sans auth",
    3389: "RDP exposé — risque d'accès à distance non autorisé",
    25: "SMTP ouvert — relayeur possible, spam potentiel",
    53: "DNS exposé — amplification DNS possible (DDoS)",
    21: "FTP non chiffré — credentials en clair",
    5900: "VNC exposé — accès graphique à distance possible",
    443: "HTTPS — vérifier la validité du certificat",
    80: "HTTP non chiffré — données en clair",
    8080: "Port alternatif HTTP — application web potentiellement exposée",
}


class NmapScanner:
    def __init__(self, target: str):
        self.target = self._extract_host(target)
        self.use_real = NMAP_USE_REAL and shutil.which("nmap") is not None

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extrait le hostname/IP de l'URL (ex: https://example.com:8080 → example.com)"""
        target = target.strip()
        if "://" in target:
            target = target.split("://")[1]
        target = target.split(":")[0]
        target = target.split("/")[0]
        return target

    def run(self) -> list:
        """Lance le scan nmap (réel ou simulé)"""
        if self.use_real:
            return self._run_real()
        return self._run_simulated()

    # ─── Mode réel (Nmap installé) ────────────────────────────────────────
    def _run_real(self) -> list:
        """
        Exécute nmap avec options :
        -sV : détection de version des services
        -sC : scripts par défaut
        -p- : tous les ports (1-65535)
        -T4 : vitesse raisonnable
        """
        findings = []
        cmd = [
            "nmap",
            "-sV",           # Version detection
            "-p-",           # All ports
            "-T4",           # Timing aggressive (but not reckless)
            "--min-rate=100",
            "-oX", "-",      # Output to stdout as XML
            self.target
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            findings = self._parse_nmap_xml(result.stdout)
            
        except subprocess.TimeoutExpired:
            findings.append({
                "owasp_id": "A02",
                "nom": "Nmap scan timeout",
                "outil": "Nmap",
                "statut": "faible",
                "technique": "Nmap timeout",
                "detail": f"Nmap scan sur {self.target} a dépassé le timeout (10 min)",
                "preuve": f"nmap -sV -p- {self.target}",
                "cvss": 0.0,
                "remediation": "Relancer le scan avec un timeout plus long ou cibler des ports spécifiques.",
                "source": "nmap_real"
            })
        except Exception as exc:
            findings.append({
                "owasp_id": "A02",
                "nom": "Erreur lors du scan Nmap",
                "outil": "Nmap",
                "statut": "faible",
                "technique": "Nmap error",
                "detail": f"Erreur : {str(exc)}",
                "preuve": f"nmap -sV -p- {self.target}",
                "cvss": 0.0,
                "remediation": "Vérifier que Nmap est installé et que la cible est accessible.",
                "source": "nmap_real"
            })
        
        return findings

    def _parse_nmap_xml(self, xml_output: str) -> list:
        """
        Parse la sortie XML de nmap et extrait les ports ouverts.
        Format simplifié — parsing basique pour éviter les dépendances XML complexes.
        """
        findings = []
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    state = port_elem.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    
                    port_num = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol", "tcp")
                    
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    service_version = service_elem.get("product", "") if service_elem is not None else ""
                    
                    finding = self._port_to_finding(port_num, protocol, service_name, service_version)
                    findings.append(finding)
        
        except Exception:
            pass
        
        return findings

    # ─── Mode simulé (tests TCP/UDP sur ports courants) ────────────────────
    def _run_simulated(self) -> list:
        """
        Teste la connectivité TCP/UDP sur les ports courants.
        Utilise le threading pour tester tous les ports en parallèle.
        """
        import concurrent.futures
        findings = []
        
        # Tester tous les ports en parallèle avec ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._test_port, self.target, port, protocol, timeout=1.0): (port, protocol, service, owasp_id, statut, cvss)
                for port, protocol, service, owasp_id, statut, cvss in COMMON_PORTS
            }
            
            for future in concurrent.futures.as_completed(futures, timeout=15):
                port, protocol, service, owasp_id, statut, cvss = futures[future]
                try:
                    is_open = future.result()
                except Exception:
                    is_open = False
                
                if is_open:
                    finding = {
                        "owasp_id": owasp_id,
                        "nom": f"Port {port} ({service}) ouvert",
                        "outil": "Nmap",
                        "statut": statut,
                        "technique": f"{protocol.upper()} connection test",
                        "detail": f"Le port {port} est ouvert et {service} pourrait tourner sur ce port.",
                        "preuve": f"{protocol.upper()} {self.target}:{port} — connexion établie",
                        "cvss": cvss,
                        "remediation": self._get_remediation(port, service),
                        "source": "nmap_simulated"
                    }
                    
                    if port in PORT_RISK_DETAILS:
                        finding["detail"] = PORT_RISK_DETAILS[port]
                    
                    findings.append(finding)
        
        # Si au moins un port est ouvert, signaler la découverte de surface d'attaque
        if findings:
            findings.insert(0, {
                "owasp_id": "A02",
                "nom": f"Surface d'attaque réseau détectée : {len(findings)} port(s) ouvert(s)",
                "outil": "Nmap",
                "statut": "moyen",
                "technique": "Port scanning simulation",
                "detail": f"Nmap a détecté {len(findings)} port(s) ouvert(s) sur {self.target}. "
                         f"Chaque port ouvert est une surface d'attaque potentielle.",
                "preuve": f"nmap -p- {self.target}",
                "cvss": 5.3,
                "remediation": "Fermer tous les ports non essentiels. Utiliser un firewall pour restreindre l'accès par IP.",
                "source": "nmap_simulated_summary"
            })
        
        return findings

    @staticmethod
    def _test_port(host: str, port: int, protocol: str = "tcp", timeout: float = 1.0) -> bool:
        """
        Teste si un port est ouvert en essayant de se connecter.
        Retourne True si le port répond, False sinon.
        """
        try:
            if protocol.lower() == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                return result == 0
            
            elif protocol.lower() == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b"", (host, port))
                try:
                    data, addr = sock.recvfrom(1)
                    sock.close()
                    return True
                except socket.timeout:
                    sock.close()
                    return False
        
        except (socket.gaierror, socket.error, OSError):
            pass
        
        return False

    def _port_to_finding(self, port: int, protocol: str, service: str, version: str) -> dict:
        """Convertit les données d'un port en finding OWASP"""
        # Mapper le port à ses risques
        default_risk = "moyen"
        default_cvss = 5.0
        default_owasp = "A02"
        
        for p, proto, svc, owasp_id, statut, cvss in COMMON_PORTS:
            if p == port and proto.lower() == protocol.lower():
                default_risk = statut
                default_cvss = cvss
                default_owasp = owasp_id
                service = svc
                break
        
        detail = PORT_RISK_DETAILS.get(port, f"Service {service} détecté sur le port {port}")
        if version:
            detail += f"\nVersion détectée : {version}"
        
        return {
            "owasp_id": default_owasp,
            "nom": f"Port {port}/{protocol} ({service}) ouvert",
            "outil": "Nmap",
            "statut": default_risk,
            "technique": f"Nmap port scan — {protocol.upper()} probe",
            "detail": detail,
            "preuve": f"nmap -p {port} {self.target} → port {port}/{protocol} open ({service})" + 
                     (f" {version}" if version else ""),
            "cvss": default_cvss,
            "remediation": self._get_remediation(port, service),
            "source": "nmap_real"
        }

    @staticmethod
    def _get_remediation(port: int, service: str) -> str:
        """Fournit une remédiation spécifique au port/service"""
        remediations = {
            22: "Restreindre SSH à des IPs autorisées. Utiliser des clés SSH. Désactiver root login.",
            25: "Configurer SMTP Auth. Restreindre les connexions à des IPs autorisées. Utiliser TLS.",
            53: "Configurer DNS sec (DNSSEC). Restreindre les requêtes récursives. Filtrer les zones.",
            80: "Forcer HTTPS sur tous les ports. Rediriger HTTP 80 → HTTPS 443.",
            110: "Chiffrer POP3 avec TLS (POP3S). Restreindre l'accès par IP.",
            143: "Chiffrer IMAP avec TLS (IMAPS). Restreindre l'accès par IP.",
            443: "Valider le certificat SSL/TLS. Utiliser TLS 1.2+. Vérifier l'expiration.",
            1433: "Ne pas exposer MSSQL. Configurer SQL Server Auth + Windows Auth. Restreindre par firewall.",
            3306: "Ne pas exposer MySQL. Configurer l'authentification. Restreindre par firewall.",
            3389: "Restreindre RDP à des IPs autorisées. Utiliser un VPN. Désactiver le compte Administrator.",
            5432: "Configurer PostgreSQL avec authentification. Restreindre par firewall. Utiliser SSL/TLS.",
            5900: "Restreindre VNC à des IPs autorisées. Utiliser un tunnel SSH. Changer le mot de passe.",
            6379: "Configurer Redis avec un mot de passe. Restreindre à localhost. Utiliser Redis ACLs.",
            8080: "Vérifier que le service n'expose rien de sensible. Mettre à jour. Restreindre l'accès.",
            21: "Désactiver FTP. Utiliser SFTP ou SCP à la place. Si FTP nécessaire : TLS obligatoire.",
            27017: "Configurer l'authentification MongoDB. Restreindre par firewall. Chiffrer les connexions.",
        }
        
        if port in remediations:
            return remediations[port]
        
        return f"Vérifier la nécessité du service {service} sur le port {port}. " \
               f"Fermer le port si inutilisé. Restreindre l'accès par firewall ou authentification."
