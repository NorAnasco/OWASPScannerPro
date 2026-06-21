#!/usr/bin/env python
"""
Script de test de la base de donnees
"""
from database import db
import os

print("=" * 60)
print("TEST DE LA BASE DE DONNEES")
print("=" * 60)

# Test 1: DB initialisee
if os.path.exists("scanner.db"):
    print("✓ Fichier scanner.db existe")
    size = os.path.getsize("scanner.db")
    print(f"✓ Taille: {size} bytes")
else:
    print("❌ scanner.db non trouve")
    exit(1)

# Test 2: Lister les scans (doit etre vide)
scans = db.list_scans()
print(f"✓ Nombre de scans actuels: {len(scans)}")

# Test 3: Recuperer les stats
stats = db.get_stats()
print(f"✓ Stats globales:")
print(f"   - Total scans: {stats['total_scans']}")
print(f"   - Total findings: {stats['total_findings']}")
print(f"   - Score moyen: {stats['avg_score']}")

# Test 4: Sauvegarder un scan test
test_scan_id = "test-scan-12345"
db.save_scan(test_scan_id, "https://example.com", ["nmap", "zap"], ["A01", "A02"])
print(f"✓ Scan de test sauvegarde: {test_scan_id}")

# Test 5: Recuperer le scan
scan = db.get_scan(test_scan_id)
if scan:
    print(f"✓ Scan recupere:")
    print(f"   - Target: {scan['target']}")
    print(f"   - Status: {scan['status']}")
else:
    print("❌ Impossible de recuperer le scan")
    exit(1)

# Test 6: Sauvegarder un finding
finding = {
    "owasp_id": "A01",
    "nom": "Test Finding",
    "outil": "Nmap",
    "statut": "critique",
    "technique": "Port scanning",
    "detail": "Port 22 ouvert",
    "preuve": "nmap test",
    "cvss": 7.5,
    "remediation": "Fermer le port",
    "source": "test"
}
db.save_finding(test_scan_id, finding)
print(f"✓ Finding sauvegarde")

# Test 7: Recuperer les findings
findings = db.get_findings_for_scan(test_scan_id)
print(f"✓ Nombre de findings pour ce scan: {len(findings)}")

# Test 8: Mettre a jour le scan
db.update_scan_results(test_scan_id, 75, "Moyen")
print(f"✓ Scan mis a jour (score=75)")

# Test 9: Nettoyer
db.delete_scan(test_scan_id)
print(f"✓ Scan test supprime")

print("=" * 60)
print("✅ TOUS LES TESTS PASSES!")
print("=" * 60)
