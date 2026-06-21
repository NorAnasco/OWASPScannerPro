# OWASP Scanner Pro v2 — Moteur de détection de vulnérabilités web

**OWASP Scanner Pro v2** est une plateforme web de scan de sécurité applicative construite autour du référentiel **OWASP Top 10 2025**. Le projet permet de lancer des scans sur des cibles web autorisées, de centraliser les findings, d’annoter manuellement les résultats, de comparer plusieurs scans, d’exporter des rapports et de gérer des projets/périmètres d’audit.

L’application est développée en **Python/Flask**, avec une interface web moderne en HTML/CSS/JavaScript, une base SQLite, un système d’authentification, une piste d’audit, un scheduler de scans et plusieurs moteurs de détection.

---

## 1. Objectif du projet

Le but du projet est de fournir un outil complet pour :

- lancer des scans web en mode simulé ou réel ;
- détecter des vulnérabilités orientées OWASP Top 10 ;
- centraliser les résultats dans une base SQLite ;
- annoter manuellement les findings ;
- comparer deux scans pour suivre l’évolution des vulnérabilités ;
- gérer des projets et périmètres d’audit ;
- générer des rapports JSON, Markdown et PDF ;
- garder une trace des actions utilisateurs via des logs d’audit ;
- planifier des scans récurrents ;
- présenter les résultats dans un dashboard clair.

Le projet est conçu pour un usage **éducatif, légal et autorisé**.

---

## 2. Technologies principales

| Élément | Technologie |
|---|---|
| Backend | Flask |
| Langage | Python |
| Base de données | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Graphiques | Chart.js |
| Authentification | Sessions Flask |
| Chiffrement | `cryptography` / Fernet |
| Export PDF | ReportLab |
| Scanner externe | OWASP ZAP, Nikto, Burp Suite, Nmap |
| IA | Analyseur compatible Claude API |
| Planification | Thread scheduler interne |

---

## 3. Structure du projet

```text
owasp-scanner-pro-v2-owasp2025/
├── app.py                         # Serveur Flask principal, routes API, pipeline de scan
├── config.py                      # Configuration centralisée
├── init_db.py                     # Initialisation de la base SQLite
├── requirements.txt               # Dépendances Python
├── schema.sql                     # Schéma SQLite de référence
├── README.md                      # Documentation complète
│
├── database/
│   ├── __init__.py                # Initialise une instance DB globale
│   ├── db.py                      # Couche d’accès aux données SQLite
│   └── schema.sql                 # Schéma de base de données
│
├── scanners/
│   ├── nmap_scanner.py            # Scanner Nmap réel/simulé
│   ├── zap_scanner.py             # Scanner OWASP ZAP réel/simulé
│   ├── nikto_scanner.py           # Scanner Nikto réel/simulé
│   ├── burp_scanner.py            # Scanner Burp réel/simulé
│   └── owasp_analyzer.py          # Analyse IA / corrélation OWASP
│
├── utils/
│   ├── audit_logger.py            # Journalisation des actions importantes
│   ├── crypto_utils.py            # Chiffrement/déchiffrement des cibles
│   ├── rate_limiter.py            # Limitation login/API
│   ├── report_generator.py        # Export JSON/Markdown/PDF
│   ├── scan_scheduler.py          # Scheduler de scans récurrents
│   └── target_validator.py        # Validation et sécurisation des cibles
│
├── templates/
│   ├── index.html                 # Interface web principale
│   └── login.html                 # Page de connexion
│
└── static/
    └── styles.css                 # Interface CSS moderne dark/light
```

---

## 4. Fonctionnalités principales

### 4.1 Authentification et rôles

Le projet intègre une authentification par session Flask.

Rôles disponibles :

- `admin`
- `auditor`

L’admin peut notamment :

- créer/supprimer des utilisateurs ;
- consulter les logs d’audit ;
- gérer les scans programmés ;
- gérer les projets ;
- effectuer des actions RGPD comme l’anonymisation d’un utilisateur.

---

### 4.2 Scan web OWASP

L’application permet de lancer un scan sur une cible web depuis l’interface.

Les outils disponibles :

| Outil | Rôle |
|---|---|
| Nmap | Cartographie réseau, ports ouverts |
| OWASP ZAP | Headers HTTP, cookies, TLS, scan passif/actif |
| Nikto | Fichiers sensibles, endpoints dangereux |
| Burp Suite | Tests d’injection, fuzzing, vulnérabilités web |
| IA | Corrélation et analyse complémentaire via analyseur OWASP |

Chaque scan peut cibler tout ou partie du référentiel **OWASP Top 10 2025**.

---

### 4.3 Mode simulé et mode réel

Le projet supporte deux modes de fonctionnement.

#### Mode simulé

Activé par défaut. Il ne nécessite pas l’installation complète des outils externes. Il permet de produire des résultats de démonstration ou d’entraînement en effectuant des contrôles légers.

#### Mode réel

Activable via `.env` si les outils sont installés/configurés :

```env
NMAP_USE_REAL=true
ZAP_USE_REAL=true
NIKTO_USE_REAL=true
BURP_USE_REAL=true
```

---

### 4.4 Pipeline de scan

Le pipeline principal se trouve dans `app.py`.

Il suit globalement ces étapes :

1. résolution DNS / empreinte de la cible ;
2. scan Nmap ;
3. scan ZAP ;
4. scan Nikto ;
5. scan Burp ;
6. analyse IA / corrélation OWASP ;
7. consolidation du rapport ;
8. sauvegarde en base ;
9. diffusion du résultat via SSE.

Le frontend reçoit la progression en temps réel grâce aux Server-Sent Events.

---

### 4.5 Gestion des findings

Un finding représente une vulnérabilité ou un résultat de scan.

Chaque finding contient notamment :

- ID OWASP ;
- nom ;
- outil ayant détecté la vulnérabilité ;
- statut de criticité ;
- technique ;
- détail ;
- preuve ;
- score CVSS ;
- recommandation de remédiation ;
- source ;
- annotation manuelle ;
- commentaires.

Statuts de criticité utilisés :

- `critique`
- `élevé`
- `moyen`
- `faible`
- `ok`

---

### 4.6 Annotations manuelles des findings

L’interface permet de valider ou invalider manuellement un finding depuis l’historique.

Statuts d’annotation disponibles :

- `Non annoté`
- `Faux positif`
- `Confirmé`
- `En correction`
- `Corrigé`

Chaque annotation peut être accompagnée d’un commentaire.

Flux typique :

1. ouvrir l’historique ;
2. cliquer sur l’icône d’œil d’un scan ;
3. ouvrir le rapport du scan ;
4. utiliser le menu d’annotation de chaque finding ;
5. ajouter un commentaire ;
6. enregistrer l’annotation.

---

### 4.7 Comparaison de scans — Diff

Le projet permet de comparer deux scans terminés.

La comparaison identifie :

- nouvelles vulnérabilités ;
- vulnérabilités corrigées ;
- findings modifiés ;
- findings stables.

Cette fonctionnalité est utile pour mesurer l’évolution entre deux campagnes de scan.

---

### 4.8 Scan multi-cibles

L’interface permet de lancer plusieurs scans en parallèle.

Utilisation :

1. ouvrir **Nouvelle analyse** ;
2. saisir plusieurs URL, une par ligne ;
3. cliquer sur **Scanner plusieurs cibles**.

Le backend crée un lot de scans, lance les threads en parallèle et conserve l’état du lot.

---

### 4.9 Gestion des projets / périmètres

Le projet inclut une gestion complète des projets d’audit.

Un projet peut contenir :

- nom ;
- client ;
- environnement ;
- description ;
- date de début ;
- date de fin ;
- scans associés.

Les scans peuvent être rattachés à un projet depuis l’interface.

Fonctionnalités disponibles :

- créer un projet ;
- modifier un projet ;
- supprimer un projet sans supprimer les scans ;
- associer un scan à un projet ;
- filtrer l’historique par projet ;
- afficher un dashboard projet ;
- consulter les statistiques par projet.

---

### 4.10 Dashboard

Le dashboard affiche des indicateurs globaux :

- nombre total de scans ;
- nombre total de findings ;
- score moyen ;
- distribution des risques ;
- évolution du score ;
- findings par ID OWASP ;
- top 5 des cibles les plus scannées.

Les données du dashboard ne sont pas codées en dur : elles viennent de la base SQLite et des logs d’audit.

---

### 4.11 Activité récente

L’activité récente a été déplacée dans l’onglet **Historique**, car elle est liée aux actions d’audit.

Elle affiche les dernières actions utilisateurs, par exemple :

- lancement de scan ;
- suppression de scan ;
- export de rapport ;
- annotation de finding ;
- comparaison de scans ;
- scan multi-cibles ;
- création/suppression de projet.

---

### 4.12 Filtres avancés dans l’historique

L’historique des scans dispose de filtres avancés :

- recherche textuelle ;
- date de début ;
- date de fin ;
- outil utilisé ;
- score minimum ;
- score maximum ;
- projet associé.

---

### 4.13 Export de rapports

Les rapports peuvent être exportés en :

- JSON ;
- Markdown ;
- PDF.

Les exports sont disponibles depuis le rapport d’un scan terminé.

Le générateur de rapport se trouve dans :

```text
utils/report_generator.py
```

---

### 4.14 Thème dark/light

L’interface supporte deux thèmes :

- dark mode ;
- light mode.

La préférence est sauvegardée localement dans le navigateur.

---

### 4.15 Support multilingue minimal

L’interface possède une base i18n minimale côté frontend.

Langues disponibles :

- Français ;
- Anglais.

Le mécanisme repose sur un dictionnaire JavaScript et des attributs `data-i18n`.

---

### 4.16 Scans programmés

Le scheduler permet de planifier des scans récurrents.

Fonctionnalités :

- créer une tâche planifiée ;
- définir un intervalle en minutes ;
- lister les tâches ;
- supprimer une tâche ;
- activer/désactiver une tâche.

---

### 4.17 Audit logs

Le projet garde une trace des actions importantes.

Actions suivies :

- connexion ;
- échec de connexion ;
- déconnexion ;
- lancement de scan ;
- suppression de scan ;
- export de rapport ;
- annotation de finding ;
- comparaison de scans ;
- scan multi-cibles ;
- création/suppression de projet ;
- création/suppression d’utilisateur ;
- anonymisation RGPD.

---

### 4.18 Isolation des données par utilisateur

Le projet applique une isolation des données selon le rôle connecté :

- les utilisateurs `admin` voient toutes les données du système ;
- les utilisateurs `auditor` voient uniquement les données qu’ils ont créées.

Cette isolation concerne notamment :

- les scans ;
- les findings associés aux scans ;
- les rapports ;
- les exports ;
- les projets ;
- les statistiques projet ;
- le dashboard ;
- les scans programmés ;
- les lots de scans multi-cibles.

Les scans et projets conservent tout de même un champ `created_by`, ce qui permet de savoir quel utilisateur les a créés.

---

### 4.19 Sécurité et confidentialité

Le projet intègre plusieurs mécanismes de sécurité :

- validation des cibles ;
- blocage des IP privées/locales pour limiter les risques SSRF ;
- chiffrement des cibles en base avec Fernet ;
- limitation des tentatives de login ;
- limitation API ;
- logs d’audit ;
- suppression/anonymisation RGPD ;
- authentification par session.

---

## 5. Base de données

La base SQLite est stockée dans :

```text
database/scanner.db
```

Le schéma principal est dans :

```text
database/schema.sql
```

### Tables principales

#### `users`

Gère les comptes utilisateurs.

Champs importants :

- `username`
- `password_hash`
- `role`
- `created_at`

#### `scans`

Stocke les scans.

Champs importants :

- `id`
- `target`
- `tools`
- `owasp_ids`
- `project_id`
- `status`
- `score`
- `risk_level`
- `started_at`
- `completed_at`
- `error_message`
- `created_by`

#### `findings`

Stocke les vulnérabilités détectées.

Champs importants :

- `scan_id`
- `owasp_id`
- `nom`
- `outil`
- `statut`
- `technique`
- `detail`
- `preuve`
- `cvss`
- `remediation`
- `source`
- `annotation_status`
- `annotation_comment`
- `annotated_by`
- `annotated_at`

#### `finding_comments`

Stocke les commentaires liés aux findings.

#### `scan_events`

Stocke les événements de progression des scans.

#### `scan_results`

Stocke les résultats consolidés des scans.

#### `audit_logs`

Stocke les actions importantes réalisées par les utilisateurs.

#### `scan_batches`

Stocke les lots de scans multi-cibles.

#### `scan_diffs`

Stocke les comparaisons de scans.

#### `projects`

Stocke les projets/périmètres d’audit.

---

## 6. Interface utilisateur

L’interface principale est dans :

```text
templates/index.html
```

Le style est dans :

```text
static/styles.css
```

### Onglets disponibles

#### Nouvelle analyse

Permet de :

- choisir un projet ;
- saisir une cible ;
- lancer un scan unique ;
- lancer un scan multi-cibles ;
- sélectionner les catégories OWASP ;
- sélectionner les outils ;
- suivre la progression du scan.

#### Dashboard

Affiche :

- KPI globaux ;
- évolution du score ;
- findings par OWASP ;
- top 5 des cibles.

#### Configuration

Affiche les informations de mode de fonctionnement et les variables utiles.

#### Projets

Permet de :

- créer un projet ;
- voir les projets existants ;
- consulter les statistiques projet ;
- supprimer un projet.

#### Rapport actuel

Affiche le rapport du scan sélectionné.

Permet aussi :

- l’annotation des findings ;
- la consultation des commentaires ;
- l’export JSON/Markdown/PDF.

#### Historique

Affiche :

- les scans ;
- les filtres avancés ;
- le diff rapide ;
- l’activité récente.

#### Administration

Réservée aux admins.

Permet de :

- créer/supprimer des utilisateurs ;
- consulter les logs d’audit ;
- gérer l’anonymisation RGPD.

---

## 7. API REST principale

| Endpoint | Méthode | Description |
|---|---:|---|
| `/api/scan/start` | POST | Démarre un scan |
| `/api/scan/stream/<id>` | GET | Stream SSE des événements |
| `/api/scan/result/<id>` | GET | Récupère le résultat final |
| `/api/scan/status/<id>` | GET | Récupère le statut courant d’un scan |
| `/api/report/<id>/json` | GET | Exporte en JSON |
| `/api/report/<id>/markdown` | GET | Exporte en Markdown |
| `/api/report/<id>/pdf` | GET | Exporte en PDF |
| `/api/scans` | GET | Liste l’historique avec filtres |
| `/api/scans/<id>` | GET | Détail complet d’un scan |
| `/api/scans/<id>` | DELETE | Supprime un scan |
| `/api/scans/diff` | POST | Compare deux scans |
| `/api/batch-scans/start` | POST | Lance plusieurs scans en parallèle |
| `/api/batch-scans/<id>` | GET | État d’un lot multi-cibles |
| `/api/projects` | GET/POST | Liste ou crée un projet |
| `/api/projects/<id>` | GET/PUT/DELETE | Lire, modifier ou supprimer un projet |
| `/api/projects/<id>/stats` | GET | Statistiques d’un projet |
| `/api/findings/<id>/annotate` | POST | Annoter un finding |
| `/api/findings/<id>/comments` | GET | Lire les commentaires d’un finding |
| `/api/dashboard/stats` | GET | Statistiques du dashboard |
| `/api/scheduler/tasks` | GET/POST | Liste ou crée une tâche planifiée |
| `/api/scheduler/tasks/<id>` | DELETE | Supprime une tâche planifiée |
| `/api/scheduler/tasks/<id>/toggle` | POST | Active/désactive une tâche |
| `/api/audit/logs` | GET | Liste les logs d’audit |
| `/api/audit/actions` | GET | Liste les actions d’audit disponibles |
| `/api/admin/add-user` | POST | Crée un utilisateur |
| `/api/admin/get-users` | GET | Liste les utilisateurs |
| `/api/admin/delete-user/<username>` | DELETE | Supprime un utilisateur |
| `/api/gdpr/forget` | POST | Anonymise/supprime les données d’un utilisateur |

---

## 8. Exemple de lancement de scan

```bash
curl -X POST http://127.0.0.1:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://testphp.vulnweb.com",
    "tools": ["zap", "nikto", "burp", "ai"],
    "owasp_ids": ["A01","A02","A03","A05","A07"]
  }'
```

---

## 9. Exemple de comparaison de scans

```bash
curl -X POST http://127.0.0.1:5000/api/scans/diff \
  -H "Content-Type: application/json" \
  -d '{
    "left_scan_id": "scan-ancien",
    "right_scan_id": "scan-nouveau"
  }'
```

---

## 10. Exemple de création de projet

```bash
curl -X POST http://127.0.0.1:5000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Audit application e-commerce",
    "client": "Client Demo",
    "environment": "staging",
    "description": "Périmètre de test OWASP Top 10 2025"
  }'
```

---

## 11. Installation rapide

### Prérequis

- Python 3.11+
- pip
- Navigateur moderne
- Optionnel : Nmap, OWASP ZAP, Nikto, Burp Suite Pro

### Créer un environnement virtuel

```bash
python -m venv venv
```

Windows :

```bash
venv\Scripts\activate
```

Linux/macOS :

```bash
source venv/bin/activate
```

### Installer les dépendances

```bash
pip install -r requirements.txt
```

### Initialiser la base

```bash
python init_db.py
```

### Lancer le serveur

```bash
python app.py
```

Puis ouvrir :

```text
http://127.0.0.1:5000
```

---

## 12. Configuration

Le projet utilise des variables d’environnement.

Exemple :

```env
SECRET_KEY=votre-secret-key
ANTHROPIC_API_KEY=votre-cle
DATABASE_URL=sqlite:///database/scanner.db

NMAP_USE_REAL=false
ZAP_USE_REAL=false
NIKTO_USE_REAL=false
BURP_USE_REAL=false

ZAP_HOST=127.0.0.1
ZAP_PORT=8080
ZAP_API_KEY=changeme

BURP_HOST=127.0.0.1
BURP_PORT=1337
BURP_API_KEY=changeme
```

---

## 13. Installation des outils réels

### Nmap

Windows :

```bash
choco install nmap
```

Linux :

```bash
sudo apt install nmap
```

macOS :

```bash
brew install nmap
```

### OWASP ZAP

Téléchargement officiel :

```text
https://www.zaproxy.org/
```

Démarrage daemon :

```bash
zap.sh -daemon -port 8080 -host 127.0.0.1
```

### Nikto

Linux :

```bash
sudo apt install nikto
```

macOS :

```bash
brew install nikto
```

### Burp Suite Pro

Burp Suite Pro doit être lancé avec l’extension REST API activée.

---

## 14. Sites de test légaux

Ces sites sont conçus pour être testés :

| Site | Description |
|---|---|
| `https://testphp.vulnweb.com` | Application PHP volontairement vulnérable |
| `https://demo.testfire.net` | Banque de test IBM AltoroMutual |
| `https://juice-shop.herokuapp.com` | OWASP Juice Shop |
| `https://webscantest.com` | Site de test dédié |

---

## 15. Ajout d’un scanner personnalisé

Créer un fichier dans `scanners/`, par exemple :

```python
class MonScanner:
    def __init__(self, target: str):
        self.target = target

    def run(self) -> list:
        return [
            {
                "owasp_id": "A05",
                "nom": "Exemple de vulnérabilité",
                "outil": "Mon Scanner",
                "statut": "élevé",
                "technique": "Technique utilisée",
                "detail": "Description détaillée",
                "preuve": "GET /path → 200",
                "cvss": 6.5,
                "remediation": "Action corrective",
                "source": "mon_scanner"
            }
        ]
```

Puis l’intégrer dans `run_scan_pipeline()` dans `app.py`.

---

## 16. Production

Pour un déploiement plus professionnel, utiliser Gunicorn + Nginx.

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 300 app:app
```

Nginx doit désactiver le buffering pour le SSE :

```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 300s;
    chunked_transfer_encoding on;
}
```

---

## 17. Bonnes pratiques d’utilisation

- Ne scanner que des cibles autorisées.
- Utiliser le mode simulé pour les démonstrations.
- Activer les outils réels uniquement si l’environnement est correctement configuré.
- Créer un projet par périmètre d’audit.
- Annoter manuellement les findings importants.
- Comparer les scans avant/après correction.
- Exporter les rapports après chaque campagne.
- Consulter régulièrement les logs d’audit.

---

## 18. Limites connues

- Le support multilingue est actuellement minimal.
- Le workflow de remédiation avancé n’est pas encore complet.
- Les notifications ne sont pas encore implémentées.
- Les tests automatisés ne sont pas encore présents.
- Le mode réel dépend de la configuration locale des outils externes.

---

## 19. Roadmap conseillée

1. Tests automatisés backend/frontend.
2. Workflow de remédiation avancé.
3. Notifications email/webhook.
4. Import de rapports ZAP/Nikto/Burp.
5. Rapports consolidés par projet.
6. Amélioration du support multilingue.
7. Hardening sécurité production.

---

## 20. Avertissement légal

> **Ce scanner doit être utilisé uniquement sur des systèmes dont vous avez l’autorisation explicite de tester.** Toute utilisation non autorisée est illégale. Les auteurs déclinent toute responsabilité en cas d’utilisation malveillante.
