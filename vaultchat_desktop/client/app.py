from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from websockets.sync.client import connect as ws_connect

from client.api import ApiClient
from client.config_store import load_config, save_config
from client.crypto import (
    decrypt_dm_message,
    decrypt_group_message,
    encrypt_dm_message,
    encrypt_group_message,
    generate_identity,
    hash_local_admin_password,
    verify_local_admin_password,
)
from client.widgets import GLOBAL_QSS, InviteDialog, PasswordDialog, SetupDialog


@dataclass
class AppState:
    server_url: str
    token: str
    user_id: str
    display_name: str
    group_id: str
    group_name: str
    group_secret: str
    is_admin: bool
    local_admin_password_hash: str | None
    enc_private: str
    enc_public: str
    sign_private: str
    sign_public: str


class WebSocketWorker(QObject):
    received = Signal(dict)
    status = Signal(str)
    failed = Signal(str)

    def __init__(self, server_url: str, token: str) -> None:
        super().__init__()
        self.server_url = server_url
        self.token = token
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        parsed = urlparse(self.server_url)
        scheme = 'wss' if parsed.scheme == 'https' else 'ws'
        ws_url = f'{scheme}://{parsed.netloc}/ws?token={self.token}'
        try:
            with ws_connect(ws_url) as ws:
                self.status.emit('Live-Verbindung aktiv')
                while self._running:
                    try:
                        raw = ws.recv(timeout=1)
                    except TimeoutError:
                        continue
                    if raw is None:
                        continue
                    self.received.emit(json.loads(raw))
        except Exception as exc:
            self.failed.emit(str(exc))


class VaultChatWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle('VaultChat Desktop')
        self.resize(1280, 820)

        self.state: AppState | None = None
        self.api: ApiClient | None = None
        self.members: List[Dict[str, Any]] = []
        self.selected_dm_user_id: str | None = None
        self.current_view = 'group'
        self.ws_thread: QThread | None = None
        self.ws_worker: WebSocketWorker | None = None

        self._build_ui()
        self._load_or_setup()

    def _build_ui(self) -> None:
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(14)

        self.sidebar = QFrame()
        self.sidebar.setObjectName('Sidebar')
        side_layout = QVBoxLayout(self.sidebar)

        self.lbl_title = QLabel('VaultChat')
        self.lbl_title.setObjectName('TitleLabel')
        side_layout.addWidget(self.lbl_title)

        self.lbl_meta = QLabel('Nicht verbunden')
        self.lbl_meta.setObjectName('SubtitleLabel')
        self.lbl_meta.setWordWrap(True)
        side_layout.addWidget(self.lbl_meta)

        self.btn_group = QPushButton('Gruppenchat')
        self.btn_group.setObjectName('PrimaryButton')
        self.btn_members = QPushButton('Mitglieder / DMs')
        self.btn_admin = QPushButton('Admin-Bereich')
        side_layout.addWidget(self.btn_group)
        side_layout.addWidget(self.btn_members)
        side_layout.addWidget(self.btn_admin)

        self.dm_list = QListWidget()
        side_layout.addWidget(QLabel('Direktnachrichten'))
        side_layout.addWidget(self.dm_list, 1)

        self.content = QFrame()
        self.content.setObjectName('Panel')
        content_layout = QVBoxLayout(self.content)

        self.chat_title = QLabel('Willkommen')
        self.chat_title.setObjectName('TitleLabel')
        content_layout.addWidget(self.chat_title)

        self.chat_subtitle = QLabel('Richte zuerst die App ein.')
        self.chat_subtitle.setObjectName('SubtitleLabel')
        content_layout.addWidget(self.chat_subtitle)

        self.chat_view = QTextEdit()
        self.chat_view.setObjectName('ChatView')
        self.chat_view.setReadOnly(True)
        content_layout.addWidget(self.chat_view, 1)

        self.composer = QTextEdit()
        self.composer.setFixedHeight(120)
        self.composer.setPlaceholderText('Nachricht eingeben …')
        content_layout.addWidget(self.composer)

        row = QHBoxLayout()
        self.btn_refresh = QPushButton('Aktualisieren')
        self.btn_send = QPushButton('Senden')
        self.btn_send.setObjectName('PrimaryButton')
        row.addWidget(self.btn_refresh)
        row.addStretch(1)
        row.addWidget(self.btn_send)
        content_layout.addLayout(row)

        root.addWidget(self.sidebar, 0)
        root.addWidget(self.content, 1)
        self.setCentralWidget(central)

        self.btn_group.clicked.connect(self.show_group_chat)
        self.btn_members.clicked.connect(self.show_members)
        self.btn_admin.clicked.connect(self.open_admin_area)
        self.btn_send.clicked.connect(self.send_current_message)
        self.btn_refresh.clicked.connect(self.refresh_current_view)
        self.dm_list.itemClicked.connect(self._on_dm_selected)

        menu = self.menuBar().addMenu('Datei')
        action_reload = QAction('Neu laden', self)
        action_reload.triggered.connect(self.refresh_current_view)
        menu.addAction(action_reload)
        action_setup = QAction('Neu einrichten', self)
        action_setup.triggered.connect(self._force_setup)
        menu.addAction(action_setup)

    def _load_or_setup(self) -> None:
        cfg = load_config()
        if not cfg:
            self._force_setup()
            return
        self._apply_config(cfg)
        self._after_login()

    def _force_setup(self) -> None:
        dialog = SetupDialog(self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            if not self.state:
                self.close()
            return
        payload = dialog.get_payload()
        try:
            self._run_setup(payload)
        except Exception as exc:
            traceback.print_exc()
            QMessageBox.critical(self, 'Einrichtung fehlgeschlagen', str(exc))
            if not self.state:
                self._force_setup()

    def _run_setup(self, payload: Dict[str, Any]) -> None:
        identity = generate_identity()
        api = ApiClient(payload['server_url'])
        if payload['mode'] == 'create':
            response = api.create_group({
                'bootstrap_password': payload['bootstrap_password'],
                'display_name': payload['display_name'],
                'group_name': payload['group_name'],
                'enc_public': identity['enc_public'],
                'sign_public': identity['sign_public'],
            })
            config = {
                'server_url': payload['server_url'],
                'token': response['token'],
                'user_id': response['user_id'],
                'display_name': payload['display_name'],
                'group_id': response['group_id'],
                'group_name': response['group_name'],
                'group_secret': response['group_secret'],
                'is_admin': True,
                'local_admin_password_hash': hash_local_admin_password(payload['local_admin_password']),
                **identity,
            }
            save_config(config)
            self._apply_config(config)
            InviteDialog(response['group_name'], response['group_secret'], self).exec()
        else:
            response = api.join_group({
                'group_secret': payload['group_secret'],
                'display_name': payload['display_name'],
                'enc_public': identity['enc_public'],
                'sign_public': identity['sign_public'],
            })
            config = {
                'server_url': payload['server_url'],
                'token': response['token'],
                'user_id': response['user_id'],
                'display_name': payload['display_name'],
                'group_id': response['group_id'],
                'group_name': response['group_name'],
                'group_secret': response['group_secret'],
                'is_admin': False,
                'local_admin_password_hash': None,
                **identity,
            }
            save_config(config)
            self._apply_config(config)
        self._after_login()

    def _apply_config(self, cfg: Dict[str, Any]) -> None:
        self.state = AppState(
            server_url=cfg['server_url'],
            token=cfg['token'],
            user_id=cfg['user_id'],
            display_name=cfg['display_name'],
            group_id=cfg['group_id'],
            group_name=cfg['group_name'],
            group_secret=cfg['group_secret'],
            is_admin=cfg['is_admin'],
            local_admin_password_hash=cfg.get('local_admin_password_hash'),
            enc_private=cfg['enc_private'],
            enc_public=cfg['enc_public'],
            sign_private=cfg['sign_private'],
            sign_public=cfg['sign_public'],
        )
        self.api = ApiClient(self.state.server_url)
        self.lbl_meta.setText(f'User: {self.state.display_name}\nGruppe: {self.state.group_name}\nServer: {self.state.server_url}')
        self.btn_admin.setEnabled(self.state.is_admin)

    def _after_login(self) -> None:
        self._load_members()
        self._start_websocket()
        self.show_group_chat()

    def _start_websocket(self) -> None:
        if not self.state:
            return
        if self.ws_worker:
            self.ws_worker.stop()
        if self.ws_thread:
            self.ws_thread.quit()
            self.ws_thread.wait(1000)
        self.ws_thread = QThread(self)
        self.ws_worker = WebSocketWorker(self.state.server_url, self.state.token)
        self.ws_worker.moveToThread(self.ws_thread)
        self.ws_thread.started.connect(self.ws_worker.run)
        self.ws_worker.received.connect(self._on_live_event)
        self.ws_worker.status.connect(lambda text: self.statusBar().showMessage(text, 3000))
        self.ws_worker.failed.connect(lambda text: self.statusBar().showMessage(f'Live-Verbindung: {text}', 5000))
        self.ws_thread.start()

    def closeEvent(self, event) -> None:
        if self.ws_worker:
            self.ws_worker.stop()
        if self.ws_thread:
            self.ws_thread.quit()
            self.ws_thread.wait(1000)
        super().closeEvent(event)

    def _load_members(self) -> None:
        if not self.api or not self.state:
            return
        self.members = self.api.get_members(self.state.token)
        self.dm_list.clear()
        for member in self.members:
            if member['id'] == self.state.user_id:
                continue
            item = QListWidgetItem(member['display_name'])
            item.setData(Qt.ItemDataRole.UserRole, member['id'])
            self.dm_list.addItem(item)

    def _member_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        for member in self.members:
            if member['id'] == user_id:
                return member
        return None

    def _on_dm_selected(self, item: QListWidgetItem) -> None:
        self.selected_dm_user_id = item.data(Qt.ItemDataRole.UserRole)
        member = self._member_by_id(self.selected_dm_user_id)
        self.current_view = 'dm'
        self.chat_title.setText(f'DM mit {member["display_name"] if member else "Unbekannt"}')
        self.chat_subtitle.setText('Direktnachrichten sind nur für euch beide lesbar.')
        self._render_dm_messages()

    def show_group_chat(self) -> None:
        if not self.state:
            return
        self.selected_dm_user_id = None
        self.current_view = 'group'
        self.chat_title.setText(f'Gruppenchat – {self.state.group_name}')
        self.chat_subtitle.setText('Ende-zu-Ende verschlüsselt über das Gruppengeheimnis.')
        self._render_group_messages()

    def show_members(self) -> None:
        self.current_view = 'members'
        self._load_members()
        lines = ['Mitglieder in deiner Gruppe:\n']
        for member in self.members:
            role = 'Admin' if member['is_admin'] else 'Mitglied'
            lines.append(f'- {member["display_name"]} ({role})')
        lines.append('\nWähle links einen Namen aus, um eine DM zu öffnen.')
        self.chat_title.setText('Mitglieder / DMs')
        self.chat_subtitle.setText('Alle DMs bleiben innerhalb der Gruppe, sind aber separat verschlüsselt.')
        self.chat_view.setPlainText('\n'.join(lines))

    def open_admin_area(self) -> None:
        if not self.state or not self.state.is_admin:
            QMessageBox.information(self, 'Kein Zugriff', 'Der Admin-Bereich ist nur für den Gruppen-Admin verfügbar.')
            return
        dialog = PasswordDialog('Admin-Bereich', 'Gib dein lokales Admin-Passwort ein, um den Admin-Bereich zu öffnen.', self)
        if dialog.exec() != dialog.DialogCode.Accepted:
            return
        if not self.state.local_admin_password_hash or not verify_local_admin_password(self.state.local_admin_password_hash, dialog.value()):
            QMessageBox.critical(self, 'Falsches Passwort', 'Das lokale Admin-Passwort ist falsch.')
            return
        self.current_view = 'admin'
        self.chat_title.setText('Admin-Bereich')
        self.chat_subtitle.setText('Lokale Admin-Verwaltung und Invite-Informationen.')
        self.chat_view.setPlainText(
            'Admin-Info\n\n'
            f'Gruppe: {self.state.group_name}\n'
            f'Server: {self.state.server_url}\n\n'
            'Der Gruppencode ist das eigentliche Root-Geheimnis deiner Gruppe.\n'
            'Teile ihn nur mit vertrauenswürdigen Leuten.\n\n'
            f'Aktueller Gruppencode:\n{self.state.group_secret}\n\n'
            'Freunde hinzufügen:\n'
            '1. App installieren lassen\n'
            '2. Server-URL senden\n'
            '3. Gruppencode senden\n'
            '4. Beitritt über den Join-Dialog\n'
        )

    def refresh_current_view(self) -> None:
        self._load_members()
        if self.current_view == 'dm' and self.selected_dm_user_id:
            self._render_dm_messages()
        elif self.current_view == 'members':
            self.show_members()
        elif self.current_view == 'admin':
            self.chat_view.setPlainText(self.chat_view.toPlainText())
        else:
            self._render_group_messages()

    def _render_group_messages(self) -> None:
        if not self.api or not self.state:
            return
        items = self.api.get_group_messages(self.state.token)
        lines: List[str] = []
        for item in items:
            sender = self._member_by_id(item['sender_user_id'])
            sender_name = sender['display_name'] if sender else 'Unbekannt'
            try:
                plaintext = decrypt_group_message(
                    envelope=item['envelope'],
                    group_secret=self.state.group_secret,
                    group_id=self.state.group_id,
                    sender_sign_public_b64=sender['sign_public'] if sender else '',
                )
            except Exception as exc:
                plaintext = f'[Entschlüsselung fehlgeschlagen: {exc}]'
            lines.append(f'[{item["created_at"]}] {sender_name}:\n{plaintext}\n')
        self.chat_view.setPlainText('\n'.join(lines) if lines else 'Noch keine Gruppennachrichten.')

    def _render_dm_messages(self) -> None:
        if not self.api or not self.state or not self.selected_dm_user_id:
            return
        items = self.api.get_dm_messages(self.state.token, self.selected_dm_user_id)
        lines: List[str] = []
        for item in items:
            sender = self._member_by_id(item['sender_user_id'])
            sender_name = sender['display_name'] if sender else 'Unbekannt'
            try:
                plaintext = decrypt_dm_message(
                    envelope=item['envelope'],
                    current_user_id=self.state.user_id,
                    recipient_enc_private_b64=self.state.enc_private,
                    sender_sign_public_b64=sender['sign_public'] if sender else '',
                )
            except Exception as exc:
                plaintext = f'[Entschlüsselung fehlgeschlagen: {exc}]'
            lines.append(f'[{item["created_at"]}] {sender_name}:\n{plaintext}\n')
        self.chat_view.setPlainText('\n'.join(lines) if lines else 'Noch keine Direktnachrichten.')

    def send_current_message(self) -> None:
        if not self.api or not self.state:
            return
        text = self.composer.toPlainText().strip()
        if not text:
            return
        try:
            if self.current_view == 'dm' and self.selected_dm_user_id:
                member = self._member_by_id(self.selected_dm_user_id)
                if not member:
                    raise RuntimeError('DM-Empfänger wurde nicht gefunden.')
                envelope = encrypt_dm_message(
                    plaintext=text,
                    sender_user_id=self.state.user_id,
                    recipient_user_id=self.selected_dm_user_id,
                    recipient_enc_public_b64=member['enc_public'],
                    sender_enc_public_b64=self.state.enc_public,
                    sender_sign_private_b64=self.state.sign_private,
                )
                self.api.send_dm_message(self.state.token, {'recipient_user_id': self.selected_dm_user_id, 'envelope': envelope})
            else:
                envelope = encrypt_group_message(
                    plaintext=text,
                    group_secret=self.state.group_secret,
                    group_id=self.state.group_id,
                    sender_user_id=self.state.user_id,
                    sender_sign_private_b64=self.state.sign_private,
                )
                self.api.send_group_message(self.state.token, envelope)
            self.composer.clear()
            self.refresh_current_view()
        except httpx.HTTPStatusError as exc:
            QMessageBox.critical(self, 'Serverfehler', exc.response.text)
        except Exception as exc:
            traceback.print_exc()
            QMessageBox.critical(self, 'Senden fehlgeschlagen', str(exc))

    def _on_live_event(self, event: Dict[str, Any]) -> None:
        etype = event.get('event')
        if etype in {'group_message', 'dm_message'}:
            self.refresh_current_view()
        elif etype == 'connected':
            self.statusBar().showMessage('Live-Verbindung aktiv', 3000)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(GLOBAL_QSS)
    window = VaultChatWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
