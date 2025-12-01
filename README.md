# distributed-log-analyzer
## Description du Projet
Système distribué de détection d'intrusions utilisant l'architecture master-worker avec Fog Computing. Le système analyse des fichiers logs en temps réel en utilisant un modèle BERT pour la classification des attaques.

## Architecture
- **Master** : Répartit la charge entre les workers via l'algorithme Round Robin
- **Workers (2 instances)** : Traitent les logs avec un modèle BERT pré-entraîné
- **Générateur de logs** : Simule la production de logs d'attaque
- **Dashboard Web** : Interface de visualisation en temps réel

## Fichiers du Projet

### Backend (Python)
- `src/master/master.py` - Serveur principal de distribution
- `src/workers/worker1.py` - Premier worker de traitement
- `src/workers/worker2.py` - Deuxième worker de traitement
- `src/simulation/log_generator.ipynb` - Simulation de génération de logs
- `model/bert_log_detector/` - Modèle BERT pour la classification

### Frontend (Web Dashboard)
- `web_dashboard/index.html` - Page d'accueil
- `web_dashboard/dashboard.html` - Tableau de bord principal
- `web_dashboard/css/` - Feuilles de style
- `web_dashboard/js/` - Scripts JavaScript

## Prérequis
- Python 3.8+
- PyTorch
- Transformers (Hugging Face)
- Flask
- Flask-CORS

## Installation

1. **Cloner le dépôt**
```bash
git clone [URL_DU_DEPOT]
cd bert_log_detector

