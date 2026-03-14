# GitHub Leak Scanner ☣️

Un scanner de secrets ultra-rapide basé sur le moteur industriel **YARA** (C++). Conçu pour traquer les clés d'API, les tokens et les mots de passe enfouis dans vos dépôts locaux ou distants, y compris dans l'historique de vos commits.

![Lint & Tests](https://img.shields.io/badge/tests-30%20passed-success?logo=pytest)
![YARA Engine](https://img.shields.io/badge/Engine-YARA_C%2B%2B-red?logo=c%2B%2B)
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)

## 🌟 Fonctionnalités Principales (v1.0)

1. **Moteur YARA Industriel** : Utilise le standard mondial de la cybersécurité pour une détection ultra-fiable et foudroyante, évitant les limites des simples regex Python.
2. **Validation Active (API Ping)** : Lorsqu'un `GitHub Token` ou une clé `AWS` est trouvé, l'outil ping silencieusement les API tierces pour vérifier si le token est **réellement valide et actif** (évitant les faux positifs flagrants).
3. **Système `.leakignore`** : Permet de whitelister en un clin d'oeil vos dossiers de tests en ajoutant un `.leakignore` à la racine (ou des commentaires `# leak-ignore` directement dans le code).
4. **Analyse de l'Historique Git** : Analyse incrémentale de tous les diffs `+` pour dénicher les secrets supprimés dans le passé.
5. **Provisionnement Autonome** : L'outil gère le téléchargement automatique des exécutables YARA portables pour votre OS (Windows/Linux/Mac). Zéro compilation C++ requise !

---

## 🚀 Installation

### Via PyPI (Recommandé)
Bientôt disponible via le gestionnaire officiel :
```bash
pip install github-leak-scanner
```

### Via les sources
```bash
git clone https://github.com/Dox46/github-leak-scanner.git
cd github-leak-scanner
pip install -r requirements.txt
```

---

## 💻 Utilisation (CLI)

Une fois installé, utilisez la commande globale `leak-scan` (ou `python src/cli.py` depuis les sources) :

```bash
# 1. Scanner une URL distante publique
leak-scan https://github.com/Dox46/github-leak-scanner

# 2. Scanner avec l'historique complet (très puissant)
leak-scan https://github.com/Dox46/github-leak-scanner --history

# 3. Scanner un dépôt privé (Nécessite un Personal Access Token)
leak-scan https://github.com/mon-client/repo-prive -t ghp_MonTokenSecret

# 4. Scanner un répertoire local directement
leak-scan ./mon-projet-local

# 5. Exporter les résultats en JSON pour de l'automatisation
leak-scan ./mon-projet-local --output rapport.json
```

---

## 🤖 Intégration Continue (GitHub Actions)

Protégez votre code avant même qu'il ne soit déployé. Ajoutez simplement ce fichier `leak-scan.yml` dans le dossier `.github/workflows/` de n'importe quel dépôt GitHub :

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Nécessaire pour analyser l'historique complet
          
      - name: YARA Leak Scanner
        uses: Dox46/github-leak-scanner@main
        with:
          target: '.'
          history: 'true'
```

L'Action GitHub bloquera le pipeline CI/CD avec un statut **FAILED** si le moindre secret de haute sévérité est détecté dans la Pull Request.

---

## 🛡️ Rédiger des règles d'exclusion (`.leakignore`)
Si l'outil déclenche de fausses alertes sur des dossiers de mocks ou de tests :

1. Créez un fichier `.leakignore` à la racine de votre projet :
```text
tests/*
mocks/fake_keys.py
```

2. Ou insérez le commentaire magique `# leak-ignore` n'importe où sur la ligne posant problème :
```python
fake_token = "AKIAIOSFODNN7EXAMPLE" # leak-ignore
```