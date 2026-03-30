from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

GLOBAL_QSS = """
QWidget {
    background-color: #0e1117;
    color: #e6edf3;
    font-family: Segoe UI, Inter, Arial;
    font-size: 13px;
}
QFrame#Sidebar {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 18px;
}
QFrame#Panel {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 18px;
}
QPushButton {
    background-color: #1f2937;
    border: 1px solid #374151;
    border-radius: 12px;
    padding: 10px 14px;
}
QPushButton:hover { background-color: #263244; }
QPushButton#PrimaryButton {
    background-color: #2563eb;
    border-color: #2563eb;
    color: white;
    font-weight: 600;
}
QLineEdit, QTextEdit, QListWidget {
    background-color: #0b1220;
    border: 1px solid #2b3648;
    border-radius: 12px;
    padding: 10px;
}
QListWidget::item { padding: 10px; border-radius: 10px; }
QListWidget::item:selected { background-color: #1d4ed8; }
QLabel#TitleLabel { font-size: 24px; font-weight: 700; }
QLabel#SubtitleLabel { color: #9ca3af; font-size: 12px; }
QTextEdit#ChatView { font-family: Consolas, Cascadia Code, monospace; font-size: 13px; }
"""


class InviteDialog(QDialog):
    def __init__(self, group_name: str, group_secret: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Gruppencode – jetzt sichern')
        self.resize(620, 320)
        layout = QVBoxLayout(self)
        title = QLabel('Dieser Gruppencode wird nur jetzt angezeigt.')
        title.setWordWrap(True)
        layout.addWidget(title)
        note = QLabel('Teile ihn nur mit Personen, die wirklich in die Gruppe dürfen. Mit diesem Code können neue Mitglieder beitreten und zukünftige Gruppennachrichten entschlüsseln.')
        note.setWordWrap(True)
        note.setObjectName('SubtitleLabel')
        layout.addWidget(note)
        box = QTextEdit()
        box.setReadOnly(True)
        box.setPlainText(f'Gruppe: {group_name}\n\nInvite-Code / Gruppen-Geheimnis:\n{group_secret}')
        layout.addWidget(box, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


class SetupDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('VaultChat einrichten')
        self.resize(520, 420)
        self.mode = 'create'
        layout = QVBoxLayout(self)
        title = QLabel('VaultChat Desktop einrichten')
        title.setObjectName('TitleLabel')
        layout.addWidget(title)
        subtitle = QLabel('Neue Gruppe erstellen oder bestehender Gruppe beitreten.')
        subtitle.setObjectName('SubtitleLabel')
        layout.addWidget(subtitle)
        mode_row = QHBoxLayout()
        self.btn_create = QPushButton('Neue Gruppe erstellen')
        self.btn_create.setObjectName('PrimaryButton')
        self.btn_join = QPushButton('Bestehender Gruppe beitreten')
        mode_row.addWidget(self.btn_create)
        mode_row.addWidget(self.btn_join)
        layout.addLayout(mode_row)
        form = QFormLayout()
        self.server_url = QLineEdit('http://127.0.0.1:8765')
        self.display_name = QLineEdit()
        self.group_name = QLineEdit('Friends')
        self.bootstrap_password = QLineEdit()
        self.bootstrap_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.group_secret = QLineEdit()
        self.local_admin_password = QLineEdit()
        self.local_admin_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.local_admin_password_repeat = QLineEdit()
        self.local_admin_password_repeat.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow('Server URL', self.server_url)
        form.addRow('Anzeigename', self.display_name)
        form.addRow('Gruppenname', self.group_name)
        form.addRow('Bootstrap-Passwort', self.bootstrap_password)
        form.addRow('Lokales Admin-Passwort', self.local_admin_password)
        form.addRow('Admin-Passwort wiederholen', self.local_admin_password_repeat)
        form.addRow('Gruppencode', self.group_secret)
        layout.addLayout(form)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setObjectName('SubtitleLabel')
        layout.addWidget(self.hint)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.btn_create.clicked.connect(lambda: self._set_mode('create'))
        self.btn_join.clicked.connect(lambda: self._set_mode('join'))
        self._set_mode('create')

    def _set_mode(self, mode: str) -> None:
        self.mode = mode
        is_create = mode == 'create'
        self.group_name.setVisible(is_create)
        self.bootstrap_password.setVisible(is_create)
        self.local_admin_password.setVisible(is_create)
        self.local_admin_password_repeat.setVisible(is_create)
        self.group_secret.setVisible(not is_create)
        self.hint.setText(
            'Erstellt die erste Gruppe auf diesem Server. Das feste Startpasswort ist nur für diesen Bootstrap gedacht.'
            if is_create else
            'Tritt einer bestehenden Gruppe über den vom Admin erhaltenen Gruppencode bei.'
        )

    def get_payload(self) -> dict:
        return {
            'mode': self.mode,
            'server_url': self.server_url.text().strip(),
            'display_name': self.display_name.text().strip(),
            'group_name': self.group_name.text().strip(),
            'bootstrap_password': self.bootstrap_password.text(),
            'group_secret': self.group_secret.text().strip(),
            'local_admin_password': self.local_admin_password.text(),
            'local_admin_password_repeat': self.local_admin_password_repeat.text(),
        }

    def accept(self) -> None:
        payload = self.get_payload()
        if not payload['server_url'] or not payload['display_name']:
            QMessageBox.warning(self, 'Fehlende Angaben', 'Bitte Server-URL und Anzeigename ausfüllen.')
            return
        if payload['mode'] == 'create':
            if not payload['group_name']:
                QMessageBox.warning(self, 'Fehlende Angaben', 'Bitte einen Gruppennamen angeben.')
                return
            if not payload['bootstrap_password']:
                QMessageBox.warning(self, 'Fehlende Angaben', 'Bitte das Bootstrap-Passwort eingeben.')
                return
            if not payload['local_admin_password'] or payload['local_admin_password'] != payload['local_admin_password_repeat']:
                QMessageBox.warning(self, 'Admin-Passwort', 'Das lokale Admin-Passwort fehlt oder stimmt nicht überein.')
                return
        else:
            if not payload['group_secret']:
                QMessageBox.warning(self, 'Fehlende Angaben', 'Bitte den Gruppencode eingeben.')
                return
        super().accept()


class PasswordDialog(QDialog):
    def __init__(self, title: str, description: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(420, 170)
        layout = QVBoxLayout(self)
        label = QLabel(description)
        label.setWordWrap(True)
        layout.addWidget(label)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> str:
        return self.password.text()
