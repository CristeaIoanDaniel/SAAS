
import socket
import hashlib
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    QFrame,
    QFileDialog,
)

from PyQt6.QtCore import Qt


class AdminTab(QWidget):

    def __init__(
        self,
        vault_host="127.0.0.1",
        vault_port=5050,
        log_callback=None,
        parent=None
    ):
        super().__init__(parent)

        self.vault_host = vault_host
        self.vault_port = vault_port
        self.log_callback = log_callback
        self.selected_file = None

        self.init_ui()

    def init_ui(self):

        self.setStyleSheet("""
            QWidget {
                background-color: #080808;
                color: #F5F5F5;
                font-family: Arial;
            }

            QFrame#card {
                background-color: #151515;
                border: 1px solid #292929;
                border-radius: 9px;
            }

            QLabel#muted {
                color: #929292;
                font-size: 11px;
            }

            QPushButton {
                background-color: #00A878;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 18px;
                font-weight: 600;
            }

            QPushButton:hover {
                background-color: #008F66;
            }

            QPushButton:disabled {
                background-color: #303030;
                color: #888888;
            }

            QPushButton#secondary {
                background-color: #252525;
                border: 1px solid #383838;
                color: #E5E5E5;
            }

            QPushButton#secondary:hover {
                background-color: #333333;
            }

            QProgressBar {
                background-color: #252525;
                border: none;
                border-radius: 4px;
                height: 8px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #00A878;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 25, 28, 25)
        layout.setSpacing(18)

        header = QHBoxLayout()

        title = QLabel("Administrator")
        title.setStyleSheet(
            "font-size: 25px; font-weight: 600;"
        )

        self.vault_connection = QLabel("VAULT: NOT VERIFIED")
        self.vault_connection.setObjectName("muted")

        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.vault_connection)

        layout.addLayout(header)

        subtitle = QLabel(
            "Backup management and infrastructure protection"
        )
        subtitle.setObjectName("muted")
        layout.addWidget(subtitle)

        grid = QGridLayout()
        grid.setSpacing(12)

        self.host_value = self.create_status_card(
            grid, "SOURCE HOST", 0
        )

        self.vault_value = self.create_status_card(
            grid, "VAULT NODE", 1
        )

        self.backup_value = self.create_status_card(
            grid, "BACKUP STATUS", 2
        )

        layout.addLayout(grid)

        backup_frame = QFrame()
        backup_frame.setObjectName("card")

        backup_layout = QVBoxLayout(backup_frame)
        backup_layout.setContentsMargins(18, 18, 18, 18)
        backup_layout.setSpacing(12)

        backup_title = QLabel("Secure backup")
        backup_title.setStyleSheet(
            "font-size: 15px; font-weight: 600;"
        )

        backup_description = QLabel(
            "Select a file to create a verified copy on the Vault node."
        )
        backup_description.setObjectName("muted")
        backup_description.setWordWrap(True)

        self.file_label = QLabel("No file selected")
        self.file_label.setObjectName("muted")
        self.file_label.setWordWrap(True)

        self.select_button = QPushButton("SELECT FILE")
        self.select_button.setObjectName("secondary")
        self.select_button.clicked.connect(self.select_file)

        self.backup_button = QPushButton(
            "CREATE SECURE BACKUP"
        )
        self.backup_button.clicked.connect(
            self.create_secure_backup
        )

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)

        self.operation_status = QLabel(
            "Waiting for an operation"
        )
        self.operation_status.setObjectName("muted")
        self.operation_status.setWordWrap(True)

        backup_layout.addWidget(backup_title)
        backup_layout.addWidget(backup_description)
        backup_layout.addWidget(self.file_label)
        backup_layout.addWidget(self.select_button)
        backup_layout.addWidget(self.backup_button)
        backup_layout.addWidget(self.progress_bar)
        backup_layout.addWidget(self.operation_status)

        layout.addWidget(backup_frame)

        integrity_frame = QFrame()
        integrity_frame.setObjectName("card")

        integrity_layout = QVBoxLayout(integrity_frame)
        integrity_layout.setContentsMargins(18, 18, 18, 18)

        integrity_title = QLabel("Data integrity")
        integrity_title.setStyleSheet(
            "font-size: 15px; font-weight: 600;"
        )

        self.hash_label = QLabel("SHA-256: —")
        self.hash_label.setObjectName("muted")
        self.hash_label.setWordWrap(True)
        self.hash_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        integrity_layout.addWidget(integrity_title)
        integrity_layout.addWidget(self.hash_label)

        layout.addWidget(integrity_frame)

        layout.addStretch()

    def create_status_card(self, grid, title, column):

        frame = QFrame()
        frame.setObjectName("card")

        card_layout = QVBoxLayout(frame)
        card_layout.setContentsMargins(16, 15, 16, 15)

        title_label = QLabel(title)
        title_label.setObjectName("muted")

        value_label = QLabel("—")
        value_label.setStyleSheet(
            "font-size: 19px; font-weight: 600;"
        )

        card_layout.addWidget(title_label)
        card_layout.addWidget(value_label)

        grid.addWidget(frame, 0, column)

        return value_label

    def select_file(self):

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select file for secure backup",
            str(Path.home()),
            "All files (*)"
        )

        if not file_path:
            return

        self.selected_file = Path(file_path)

        self.file_label.setText(
            f"Selected: {self.selected_file.name}"
        )

        self.operation_status.setText(
            "File selected. Ready for backup."
        )

        self.backup_value.setText("PENDING")
        self.hash_label.setText("SHA-256: —")
        self.progress_bar.setValue(0)

    def calculate_sha256(self, data):

        return hashlib.sha256(data).hexdigest()

    def create_secure_backup(self):

        if self.selected_file is None:
            self.operation_status.setText(
                "Please select a file first."
            )
            return

        if not self.selected_file.is_file():
            self.operation_status.setText(
                "Selected file is no longer available."
            )
            return

        self.select_button.setEnabled(False)
        self.backup_button.setEnabled(False)
        self.progress_bar.setValue(10)

        client = None

        try:

            self.operation_status.setText(
                "Reading selected file..."
            )

            with self.selected_file.open("rb") as file:
                payload = file.read()

            original_hash = self.calculate_sha256(payload)

            self.hash_label.setText(
                f"SHA-256: {original_hash}"
            )

            self.progress_bar.setValue(25)

            header = (
                f"{len(payload)}:{original_hash}\n"
            ).encode("ascii")

            self.operation_status.setText(
                "Connecting to Vault..."
            )

            client = socket.create_connection(
                (self.vault_host, self.vault_port),
                timeout=5
            )

            client.settimeout(10)

            self.vault_connection.setText(
                "VAULT: CONNECTED"
            )

            self.progress_bar.setValue(40)

            client.sendall(header + payload)

            self.operation_status.setText(
                "Waiting for Vault verification..."
            )

            response = b""

            while not response.endswith(b"\n"):
                chunk = client.recv(1024)

                if not chunk:
                    raise ConnectionError(
                        "Vault closed the connection."
                    )

                response += chunk

            ack = response.decode("utf-8").strip()

            if ack != "ACK_STORED":
                raise RuntimeError(
                    f"Vault rejected backup: {ack}"
                )

            self.progress_bar.setValue(100)

            self.backup_value.setText("CONFIRMED")

            self.operation_status.setText(
                "Backup stored and verified by Vault. Original preserved."
            )

            self._log(
                f"[SUCCESS] Backup confirmed for {self.selected_file.name}"
            )

            self._log(
                f"[INTEGRITY] SHA-256: {original_hash}"
            )

            self._log(
                "[INFO] Original file was not modified or deleted."
            )

        except Exception as error:

            self.progress_bar.setValue(0)

            self.backup_value.setText("FAILED")

            self.operation_status.setText(
                f"Backup failed: {error}"
            )

            self._log(
                f"[ERROR] Backup failed: {error}"
            )

        finally:

            if client is not None:
                client.close()

            self.select_button.setEnabled(True)
            self.backup_button.setEnabled(True)

    def _log(self, message):

        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)
