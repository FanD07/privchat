# VaultChat Desktop

Ein kleiner E2EE-Gruppenchat mit Desktop-Client (PySide6) und Relay-Server (FastAPI).

## Features
- Desktop-App mit moderner Qt-Oberfläche
- Gruppenchat
- DMs innerhalb derselben Gruppe
- Admin-Bootstrap mit `admin` nur für die erste Gruppenerstellung
- Danach echter zufälliger Gruppencode / Invite-Code
- Gruppenchat: AES-256-GCM aus Gruppencode via HKDF
- DMs: X25519 + HKDF + AES-256-GCM + Ed25519-Signaturen
- Relay-Server sieht nur Ciphertext-Hüllen

## Start
```bash
pip install -r requirements.txt
uvicorn server.app:app --host 127.0.0.1 --port 8765 --reload
python -m client.app
```
