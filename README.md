# Générateur WireGuard

Application web développée lors d'un stage, permettant de gérer des utilisateurs et de générer des configurations de tunnels VPN WireGuard.

---

## Technologies utilisées

- Python 3 / Flask
- MySQL / MariaDB
- HTML / CSS / JavaScript
- WireGuard (algorithme Curve25519)

## Fonctionnalités

- Création et gestion d'utilisateurs
- Génération automatique de clés WireGuard
- Génération de fichiers `.conf` téléchargeables
- Validation des données (IP, DNS, Endpoint, AllowedIPs)
- Authentification admin
- Barre de recherche

---

## Structure du projet

```
Projet-WireGuard/
├── .venv/
├── static/
│   ├── style.css
│   └── script.js
├── templates/
│   ├── index.html
│   ├── login.html
│   └── mentions_legales.html
├── configs/
├── app.py
├── .env
├── .env.example
├── .gitignore
└── requirements.txt
```

---

## Auteur

**Nciri Wiam** — Projet réalisé dans le cadre d'un stage.
