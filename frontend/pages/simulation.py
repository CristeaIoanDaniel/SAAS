
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QFormLayout, QPushButton, QSpinBox,
    QDoubleSpinBox, QComboBox, QLineEdit, QGridLayout
)

BG = "#0b0d0e"
CARD = "#141719"
BORDER = "#22272b"
GREEN = "#00e5a3"
BLUE = "#38bdf8"
RED = "#ff3b5c"
ORANGE = "#fb923c"
YELLOW = "#facc15"
TEXT = "#e5e7eb"
MUTED = "#8b949e"


def outline_button(color):
    return f"""
        QPushButton {{
            background-color: transparent;
            color: {color};
            border: 1px solid {color};
            border-radius: 6px;
            padding: 7px 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {color};
            color: {BG};
        }}
        QPushButton:disabled {{
            color: {BORDER};
            border: 1px solid {BORDER};
        }}
    """


class SimulationTab(QWidget):

    data_ready = pyqtSignal(dict)
    mode_changed = pyqtSignal(bool)

    PRESETS = {
        "Normal": {
            "risk_score": 1.0,
            "cpu_percent": 18,
            "disk_io_percent": 12,
            "recovery_readiness_percent": 100,
            "replication_speed_mbps": 85.0,
            "replication_lag_seconds": 1,
            "pending_blocks": 0,
            "replication_remaining_mb": 0,
            "replication_progress_percent": 100.0,
            "primary_status": "ONLINE",
            "secondary_status": "STANDBY",
            "integrity_status": "VERIFIED",
            "failover_status": "STANDBY",
            "isolation_status": "CONNECTED"
        },
        "Attack in progress": {
            "risk_score": 5.8,
            "cpu_percent": 94,
            "disk_io_percent": 97,
            "recovery_readiness_percent": 92,
            "replication_speed_mbps": 85.0,
            "replication_lag_seconds": 12,
            "pending_blocks": 1200,
            "replication_remaining_mb": 48000,
            "replication_progress_percent": 20.0,
            "primary_status": "UNDER ATTACK",
            "secondary_status": "STANDBY",
            "integrity_status": "COMPROMISED",
            "failover_status": "STANDBY",
            "isolation_status": "CONNECTED"
        },
        "Migration in progress": {
            "risk_score": 5.4,
            "cpu_percent": 40,
            "disk_io_percent": 88,
            "recovery_readiness_percent": 95,
            "replication_speed_mbps": 110.0,
            "replication_lag_seconds": 4,
            "pending_blocks": 80000,
            "replication_remaining_mb": 640000,
            "replication_progress_percent": 35.0,
            "primary_status": "ISOLATED",
            "secondary_status": "SYNCING",
            "integrity_status": "CHECKING",
            "failover_status": "MIGRATING",
            "isolation_status": "ISOLATED"
        },
        "Failover completed": {
            "risk_score": 5.2,
            "cpu_percent": 5,
            "disk_io_percent": 3,
            "recovery_readiness_percent": 100,
            "replication_speed_mbps": 0.0,
            "replication_lag_seconds": 0,
            "pending_blocks": 0,
            "replication_remaining_mb": 0,
            "replication_progress_percent": 100.0,
            "primary_status": "ISOLATED",
            "secondary_status": "ACTIVE",
            "integrity_status": "VERIFIED",
            "failover_status": "ACTIVE",
            "isolation_status": "ISOLATED"
        }
    }

    def __init__(self):
        super().__init__()

        self.fields = {}
        self.pending_events = []
        self.event_counter = 0

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {BG};
                color: {TEXT};
                font-family: Helvetica, sans-serif;
            }}

            QFrame#simCard {{
                background-color: {CARD};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}

            QLabel {{
                background: transparent;
                border: none;
                color: {MUTED};
                font-size: 11px;
            }}

            QSpinBox, QDoubleSpinBox, QComboBox, QLineEdit {{
                background-color: {BG};
                border: 1px solid {BORDER};
                border-radius: 6px;
                padding: 4px 8px;
                color: {TEXT};
                min-height: 22px;
            }}

            QSpinBox:focus, QDoubleSpinBox:focus,
            QComboBox:focus, QLineEdit:focus {{
                border: 1px solid {GREEN};
            }}

            QComboBox QAbstractItemView {{
                background-color: {CARD};
                color: {TEXT};
                border: 1px solid {BORDER};
                selection-background-color: {BORDER};
            }}
        """)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.send_data)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        header = QHBoxLayout()

        title = QLabel("SIMULATION")
        title.setStyleSheet(
            f"color: {TEXT}; font-size: 23px; font-weight: bold;"
        )

        self.state_label = QLabel("● SIMULATION STOPPED")
        self.state_label.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold;"
        )

        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.state_label)
        main_layout.addLayout(header)

        description = QLabel(
            "Configure simulated system conditions. "
            "Start the simulation to send values to the dashboard. "
            "Changes are sent every 2 seconds."
        )
        description.setWordWrap(True)
        main_layout.addWidget(description)

        controls = QHBoxLayout()
        controls.setSpacing(8)

        self.toggle_button = QPushButton("▶ Start simulation")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle_button.setStyleSheet(outline_button(GREEN))
        self.toggle_button.toggled.connect(self.set_active)

        self.apply_button = QPushButton("Apply now")
        self.apply_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.apply_button.setStyleSheet(outline_button(BLUE))
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self.send_data)

        controls.addWidget(self.toggle_button)
        controls.addWidget(self.apply_button)
        controls.addStretch()
        controls.addWidget(QLabel("Scenarios:"))

        for name in self.PRESETS:
            button = QPushButton(name)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setStyleSheet(outline_button(MUTED))
            button.clicked.connect(
                lambda _checked=False, preset=name: self.load_preset(preset)
            )
            controls.addWidget(button)

        main_layout.addLayout(controls)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()

        grid = QGridLayout(content)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        risk_card, risk_form = self.make_card("RISK & RESOURCES")

        risk_form.addRow(
            "Risk score (0–6)",
            self.spin("risk_score", 0, 6, 1.0, decimals=1, step=0.1)
        )
        risk_form.addRow(
            "CPU",
            self.spin("cpu_percent", 0, 100, 18, suffix=" %")
        )
        risk_form.addRow(
            "Disk I/O",
            self.spin("disk_io_percent", 0, 100, 12, suffix=" %")
        )
        risk_form.addRow(
            "Recovery readiness",
            self.spin(
                "recovery_readiness_percent", 0, 100, 100, suffix=" %"
            )
        )

        servers_card, servers_form = self.make_card("SERVER STATUS")

        servers_form.addRow(
            "Primary server",
            self.combo(
                "primary_status",
                ["ONLINE", "UNDER ATTACK", "DEGRADED", "ISOLATED", "OFFLINE"]
            )
        )
        servers_form.addRow(
            "Secondary server",
            self.combo(
                "secondary_status",
                ["STANDBY", "SYNCING", "ACTIVE", "OFFLINE"]
            )
        )
        servers_form.addRow(
            "Data integrity",
            self.combo(
                "integrity_status",
                ["VERIFIED", "CHECKING", "COMPROMISED"]
            )
        )
        servers_form.addRow(
            "Failover status",
            self.combo(
                "failover_status",
                ["STANDBY", "MIGRATING", "ACTIVE"]
            )
        )
        servers_form.addRow(
            "Network isolation",
            self.combo(
                "isolation_status",
                ["CONNECTED", "ISOLATED"]
            )
        )

        replication_card, replication_form = self.make_card("REPLICATION")

        replication_form.addRow(
            "Transfer speed",
            self.spin(
                "replication_speed_mbps", 0, 100000, 85.0,
                decimals=1, step=5, suffix=" MB/s"
            )
        )
        replication_form.addRow(
            "Replication lag",
            self.spin(
                "replication_lag_seconds", 0, 86400, 1, suffix=" s"
            )
        )
        replication_form.addRow(
            "Pending blocks",
            self.spin("pending_blocks", 0, 2000000000, 0)
        )
        replication_form.addRow(
            "Remaining data",
            self.spin(
                "replication_remaining_mb", 0, 2000000000, 0, suffix=" MB"
            )
        )
        replication_form.addRow(
            "Progress",
            self.spin(
                "replication_progress_percent", 0, 100, 100.0,
                decimals=1, step=1, suffix=" %"
            )
        )

        event_card, event_form = self.make_card("MANUAL EVENT")

        self.event_severity = QComboBox()
        self.event_severity.addItems(
            ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
        )

        self.event_message = QLineEdit()
        self.event_message.setPlaceholderText(
            "e.g. Suspicious login detected"
        )
        self.event_message.returnPressed.connect(self.add_event)

        self.event_button = QPushButton("Add event")
        self.event_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.event_button.setStyleSheet(outline_button(BLUE))
        self.event_button.setEnabled(False)
        self.event_button.clicked.connect(self.add_event)

        event_form.addRow("Severity", self.event_severity)
        event_form.addRow("Message", self.event_message)
        event_form.addRow(self.event_button)

        grid.addWidget(risk_card, 0, 0)
        grid.addWidget(servers_card, 0, 1)
        grid.addWidget(replication_card, 1, 0)
        grid.addWidget(event_card, 1, 1)

        scroll.setWidget(content)
        main_layout.addWidget(scroll)

    def make_card(self, title):
        card = QFrame()
        card.setObjectName("simCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        label = QLabel(title)
        label.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold;"
        )

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )

        layout.addWidget(label)
        layout.addLayout(form)
        layout.addStretch()

        return card, form

    def spin(self, key, minimum, maximum, value,
             decimals=0, step=1, suffix=""):

        if decimals:
            widget = QDoubleSpinBox()
            widget.setDecimals(decimals)
            widget.setRange(float(minimum), float(maximum))
            widget.setSingleStep(float(step))
            widget.setValue(float(value))
        else:
            widget = QSpinBox()
            widget.setRange(int(minimum), int(maximum))
            widget.setSingleStep(int(step))
            widget.setValue(int(value))

        widget.setSuffix(suffix)
        widget.setGroupSeparatorShown(True)
        self.fields[key] = widget

        return widget

    def combo(self, key, options):
        widget = QComboBox()
        widget.addItems(options)
        self.fields[key] = widget
        return widget

    def build_data(self):
        data = {}

        for key, widget in self.fields.items():
            if isinstance(widget, QComboBox):
                data[key] = widget.currentText()
            else:
                data[key] = widget.value()

        data["events"] = self.pending_events
        self.pending_events = []

        return data

    def send_data(self):
        if self.toggle_button.isChecked():
            self.data_ready.emit(self.build_data())

    def add_event(self):
        message = self.event_message.text().strip()

        if not message or not self.toggle_button.isChecked():
            return

        self.event_counter += 1

        self.pending_events.append({
            "id": f"sim-{self.event_counter}",
            "timestamp": datetime.now().isoformat(),
            "severity": self.event_severity.currentText(),
            "message": message
        })

        self.event_message.clear()
        self.send_data()

    def load_preset(self, name):
        for key, value in self.PRESETS[name].items():
            widget = self.fields[key]

            if isinstance(widget, QComboBox):
                widget.setCurrentText(value)
            else:
                widget.setValue(value)

        if self.toggle_button.isChecked():
            self.send_data()

    def set_active(self, active):
        self.apply_button.setEnabled(active)
        self.event_button.setEnabled(active)

        if active:
            self.toggle_button.setText("■ Stop simulation")
            self.toggle_button.setStyleSheet(outline_button(RED))

            self.state_label.setText("● SIMULATION ACTIVE")
            self.state_label.setStyleSheet(
                f"color: {ORANGE}; font-size: 10px; font-weight: bold;"
            )

            self.mode_changed.emit(True)
            self.send_data()
            self.timer.start()

        else:
            self.timer.stop()

            self.toggle_button.setText("▶ Start simulation")
            self.toggle_button.setStyleSheet(outline_button(GREEN))

            self.state_label.setText("● SIMULATION STOPPED")
            self.state_label.setStyleSheet(
                f"color: {MUTED}; font-size: 10px; font-weight: bold;"
            )

            self.mode_changed.emit(False)
