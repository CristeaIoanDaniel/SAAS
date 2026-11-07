
"""
OBSIDIAN - Resilience & Failover Dashboard
Live backend integration

Install:
    pip install PyQt6 pyqtgraph requests

Configure:
    OBSIDIAN_API_URL=http://127.0.0.1:8000/api/dashboard
    OBSIDIAN_API_TOKEN=your_token (optional)
"""

import sys
import os
import ctypes
from datetime import datetime

import requests
import pyqtgraph as pg

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QGridLayout,
    QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea
)


# ============================================================
# THEME
# ============================================================

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


# ============================================================
# BACKEND CONNECTION
# ============================================================

class BackendWorker(QThread):

    data_received = pyqtSignal(dict)
    connection_error = pyqtSignal(str)

    def __init__(
            self,
            api_url,
            token=None,
            interval_seconds=2,
            parent=None
    ):
        super().__init__(parent)

        self.api_url = api_url.rstrip("/")
        self.token = token
        self.interval_seconds = interval_seconds

    def run(self):

        headers = {
            "Accept": "application/json"
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        while not self.isInterruptionRequested():

            try:
                response = requests.get(
                    self.api_url,
                    headers=headers,
                    timeout=5
                )

                response.raise_for_status()

                data = response.json()

                if not isinstance(data, dict):
                    raise ValueError(
                        "Backend must return a JSON object."
                    )

                self.data_received.emit(data)

            except requests.RequestException as error:
                self.connection_error.emit(str(error))

            except ValueError as error:
                self.connection_error.emit(
                    f"Invalid JSON response: {error}"
                )

            # Refresh every 2 seconds.
            for _ in range(self.interval_seconds * 10):

                if self.isInterruptionRequested():
                    return

                self.msleep(100)


# ============================================================
# BASE MODULE
# ============================================================

class DashboardCard(QFrame):

    def __init__(self):
        super().__init__()

        self.setCursor(
            Qt.CursorShape.PointingHandCursor
        )

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {CARD};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}

            QFrame:hover {{
                border: 1px solid {GREEN};
            }}
        """)

    def set_expanded(self, expanded):
        pass


def configure_plot(plot, minimum=0, maximum=100):

    plot.setBackground(CARD)
    plot.setYRange(minimum, maximum)
    plot.hideAxis("bottom")
    plot.showGrid(x=False, y=True, alpha=0.15)

    plot.setAttribute(
        Qt.WidgetAttribute.WA_TransparentForMouseEvents
    )

    plot.getAxis("left").setTextPen(MUTED)
    plot.getAxis("left").setPen(
        pg.mkPen(BORDER)
    )


# ============================================================
# RISK LEVEL
# ============================================================

class CompactRiskWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        self.time_series = [0]
        self.risk_data = [0]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(7)

        top = QHBoxLayout()

        title = QLabel("RISK LEVEL  ⤢")
        title.setStyleSheet(
            f"color: {MUTED}; font-size: 11px;"
            "font-weight: bold; border: none;"
        )

        self.score_label = QLabel("-- / 5")
        self.score_label.setStyleSheet(
            f"color: {GREEN}; font-size: 17px;"
            "font-weight: bold; border: none;"
        )

        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.score_label)

        layout.addLayout(top)

        self.plot = pg.PlotWidget()

        configure_plot(self.plot, 0, 6)

        self.plot.setMinimumHeight(85)
        self.plot.setMaximumHeight(100)

        self.curve = self.plot.plot(
            self.time_series,
            self.risk_data,
            pen=pg.mkPen(GREEN, width=2)
        )

        self.threshold = pg.InfiniteLine(
            pos=5,
            angle=0,
            pen=pg.mkPen(
                RED,
                width=1.5,
                style=Qt.PenStyle.DashLine
            )
        )

        self.plot.addItem(self.threshold)

        layout.addWidget(self.plot)

        self.status = QLabel("● WAITING FOR DATA")
        self.status.setStyleSheet(
            f"color: {GREEN}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        layout.addWidget(self.status)

    def update_score(self, score):

        if score < 0:
            return

        if score > 5:
            color = RED
            status = "● CRITICAL RISK"

        elif score >= 4:
            color = ORANGE
            status = "● HIGH RISK"

        elif score >= 3:
            color = YELLOW
            status = "● ELEVATED RISK"

        elif score >= 2:
            color = BLUE
            status = "● MODERATE RISK"

        else:
            color = GREEN
            status = "● LOW RISK"

        self.score_label.setText(
            f"{score:.1f} / 5"
        )

        self.score_label.setStyleSheet(
            f"color: {color}; font-size: 17px;"
            "font-weight: bold; border: none;"
        )

        self.status.setText(status)

        self.status.setStyleSheet(
            f"color: {color}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        self.time_series.append(
            self.time_series[-1] + 1
        )

        self.risk_data.append(score)

        self.curve.setPen(
            pg.mkPen(color, width=2)
        )

        self.curve.setData(
            self.time_series[-20:],
            self.risk_data[-20:]
        )

    def set_expanded(self, expanded):

        self.plot.setMaximumHeight(
            16777215 if expanded else 100
        )

        if expanded:
            self.plot.showAxis("bottom")
        else:
            self.plot.hideAxis("bottom")


# ============================================================
# SYSTEM RESOURCES
# ============================================================

class CompactResourcesWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        self.time_series = [0]
        self.cpu_data = [0]
        self.io_data = [0]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(7)

        top = QHBoxLayout()

        title = QLabel("SYSTEM RESOURCES  ⤢")

        title.setStyleSheet(
            f"color: {MUTED}; font-size: 11px;"
            "font-weight: bold; border: none;"
        )

        self.values = QLabel("CPU --% | IO --%")

        self.values.setStyleSheet(
            f"color: {GREEN}; font-size: 12px;"
            "font-weight: bold; border: none;"
        )

        top.addWidget(title)
        top.addStretch()
        top.addWidget(self.values)

        layout.addLayout(top)

        self.plot = pg.PlotWidget()

        configure_plot(self.plot, 0, 100)

        self.plot.setMinimumHeight(85)
        self.plot.setMaximumHeight(100)

        self.cpu_curve = self.plot.plot(
            self.time_series,
            self.cpu_data,
            pen=pg.mkPen(GREEN, width=2)
        )

        self.io_curve = self.plot.plot(
            self.time_series,
            self.io_data,
            pen=pg.mkPen(BLUE, width=2)
        )

        layout.addWidget(self.plot)

        legend = QLabel("● CPU       ● DISK I/O")

        legend.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; border: none;"
        )

        layout.addWidget(legend)

    def update_resources(self, cpu, disk_io):

        self.values.setText(
            f"CPU {cpu:.0f}% | IO {disk_io:.0f}%"
        )

        self.time_series.append(
            self.time_series[-1] + 1
        )

        self.cpu_data.append(cpu)
        self.io_data.append(disk_io)

        self.cpu_curve.setData(
            self.time_series[-20:],
            self.cpu_data[-20:]
        )

        self.io_curve.setData(
            self.time_series[-20:],
            self.io_data[-20:]
        )

    def set_expanded(self, expanded):

        self.plot.setMaximumHeight(
            16777215 if expanded else 100
        )

        if expanded:
            self.plot.showAxis("bottom")
        else:
            self.plot.hideAxis("bottom")


# ============================================================
# INFORMATION CARD
# ============================================================

class InfoCard(DashboardCard):

    def __init__(
            self,
            title,
            value,
            subtitle="",
            accent=TEXT
    ):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        self.title = QLabel(title.upper())

        self.title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        self.value = QLabel(value)

        self.value.setStyleSheet(
            f"color: {accent}; font-size: 18px;"
            "font-weight: bold; border: none;"
        )

        self.subtitle = QLabel(subtitle)
        self.subtitle.setWordWrap(True)

        self.subtitle.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; border: none;"
        )

        layout.addWidget(self.title)
        layout.addWidget(self.value)
        layout.addWidget(self.subtitle)
        layout.addStretch()

    def update_value(self, value, subtitle=None):

        self.value.setText(str(value))

        if subtitle is not None:
            self.subtitle.setText(str(subtitle))


# ============================================================
# REPLICATION ENGINE
# ============================================================

class ReplicationWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        title = QLabel("REPLICATION ENGINE")

        title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        self.status = QLabel("● WAITING FOR DATA")

        self.status.setStyleSheet(
            f"color: {GREEN}; font-size: 17px;"
            "font-weight: bold; border: none;"
        )

        self.speed = QLabel("Transfer speed: -- MB/s")
        self.lag = QLabel("Replication lag: -- sec")
        self.pending = QLabel("Pending blocks: --")

        for widget in (
                self.speed,
                self.lag,
                self.pending
        ):
            widget.setStyleSheet(
                f"color: {MUTED}; font-size: 10px; border: none;"
            )

        layout.addWidget(title)
        layout.addWidget(self.status)
        layout.addWidget(self.speed)
        layout.addWidget(self.lag)
        layout.addWidget(self.pending)
        layout.addStretch()

    def update_replication(
            self,
            speed,
            lag,
            pending
    ):

        self.speed.setText(
            f"Transfer speed: {speed} MB/s"
        )

        self.lag.setText(
            f"Replication lag: {lag} sec"
        )

        self.pending.setText(
            f"Pending blocks: {pending}"
        )


# ============================================================
# EVENT LOG
# ============================================================

class EventLogWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        title = QLabel(
            "SECURITY & RECOVERY EVENTS"
        )

        title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        layout.addWidget(title)

        self.events_layout = QVBoxLayout()
        self.events_layout.setSpacing(7)

        layout.addLayout(self.events_layout)
        layout.addStretch()

        self.add_event(
            "Waiting for backend data...",
            "INFO",
            MUTED
        )

    def add_event(
            self,
            message,
            severity="INFO",
            color=MUTED
    ):

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        label = QLabel(
            f"[{timestamp}] [{severity}] {message}"
        )

        label.setWordWrap(True)

        label.setStyleSheet(
            f"color: {color}; font-size: 10px; border: none;"
        )

        self.events_layout.addWidget(label)


# ============================================================
# MAIN SECURITY TAB
# ============================================================

class SecurityTab(QWidget):

    def __init__(self):
        super().__init__()

        self.setAttribute(
            Qt.WidgetAttribute.WA_StyledBackground,
            True
        )

        self.setStyleSheet(
            f"background-color: {BG};"
            "font-family: 'Segoe UI', sans-serif;"
        )

        main_layout = QVBoxLayout(self)

        main_layout.setContentsMargins(
            18, 16, 18, 16
        )

        main_layout.setSpacing(12)

        # HEADER

        header = QHBoxLayout()

        brand = QLabel("OBSIDIAN")

        brand.setStyleSheet(
            f"color: {TEXT}; font-size: 23px;"
            "font-weight: bold; border: none;"
        )

        subtitle = QLabel(
            "RESILIENCE & FAILOVER"
        )

        subtitle.setStyleSheet(
            f"color: {MUTED}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        self.system_status = QLabel(
            "● WAITING FOR BACKEND"
        )

        self.system_status.setStyleSheet(
            f"color: {YELLOW}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        header.addWidget(brand)
        header.addSpacing(14)
        header.addWidget(subtitle)
        header.addStretch()
        header.addWidget(self.system_status)

        main_layout.addLayout(header)

        # SCROLL AREA

        scroll = QScrollArea()

        scroll.setWidgetResizable(True)

        scroll.setFrameShape(
            QFrame.Shape.NoFrame
        )

        scroll.setStyleSheet(
            "background: transparent;"
        )

        content = QWidget()

        content.setStyleSheet(
            f"background-color: {BG};"
        )

        self.grid = QGridLayout(content)

        self.grid.setContentsMargins(
            0, 0, 0, 0
        )

        self.grid.setSpacing(12)

        for col in range(4):
            self.grid.setColumnStretch(col, 1)

        for row in range(3):
            self.grid.setRowStretch(row, 1)

        scroll.setWidget(content)

        main_layout.addWidget(scroll)

        self.expanded_widget = None
        self.seen_backend_events = set()

        # MODULES

        self.risk_module = CompactRiskWidget()

        self.resources_module = CompactResourcesWidget()

        self.primary = InfoCard(
            "Primary Server",
            "WAITING",
            "Waiting for backend data",
            GREEN
        )

        self.secondary = InfoCard(
            "Secondary Server",
            "WAITING",
            "Waiting for backend data",
            BLUE
        )

        self.replication = ReplicationWidget()

        self.integrity = InfoCard(
            "Data Integrity",
            "WAITING",
            "Waiting for backend data",
            GREEN
        )

        self.recovery = InfoCard(
            "Recovery Readiness",
            "--",
            "Waiting for backend data",
            GREEN
        )

        self.failover = InfoCard(
            "Failover Status",
            "WAITING",
            "Waiting for backend data",
            GREEN
        )

        self.events = EventLogWidget()

        # GRID POSITIONS

        self.layout_items = [

            (self.risk_module, 0, 0, 1, 2),

            (self.resources_module, 0, 2, 1, 2),

            (self.primary, 1, 0, 1, 1),

            (self.secondary, 1, 1, 1, 1),

            (self.replication, 1, 2, 1, 1),

            (self.integrity, 1, 3, 1, 1),

            (self.recovery, 2, 0, 1, 1),

            (self.failover, 2, 1, 1, 1),

            (self.events, 2, 2, 1, 2)
        ]

        for widget, row, col, rs, cs in self.layout_items:

            self.grid.addWidget(
                widget,
                row,
                col,
                rs,
                cs
            )

            widget.mousePressEvent = (
                self.create_click_handler(widget)
            )

    # ========================================================
    # RECEIVE BACKEND DATA
    # ========================================================

    def apply_backend_data(self, data):

        # RISK LEVEL

        risk = data.get("risk_score")

        if isinstance(risk, (int, float)):
            self.risk_module.update_score(
                float(risk)
            )

        # SYSTEM RESOURCES

        cpu = data.get("cpu_percent")
        disk_io = data.get("disk_io_percent")

        if (
                isinstance(cpu, (int, float))
                and isinstance(disk_io, (int, float))
        ):
            self.resources_module.update_resources(
                float(cpu),
                float(disk_io)
            )

        # PRIMARY SERVER

        if data.get("primary_status") is not None:

            self.primary.update_value(
                str(data["primary_status"]).upper(),
                data.get(
                    "primary_details",
                    "Live status from backend"
                )
            )

        # SECONDARY SERVER

        if data.get("secondary_status") is not None:

            self.secondary.update_value(
                str(data["secondary_status"]).upper(),
                data.get(
                    "secondary_details",
                    "Live status from backend"
                )
            )

        # REPLICATION

        replication_keys = (
            "replication_speed_mbps",
            "replication_lag_seconds",
            "pending_blocks"
        )

        if all(
                isinstance(data.get(key), (int, float))
                for key in replication_keys
        ):

            self.replication.update_replication(
                data["replication_speed_mbps"],
                data["replication_lag_seconds"],
                data["pending_blocks"]
            )

        # DATA INTEGRITY

        if data.get("integrity_status") is not None:

            self.integrity.update_value(
                str(data["integrity_status"]).upper(),
                data.get(
                    "integrity_details",
                    "Live status from backend"
                )
            )

        # RECOVERY READINESS

        recovery = data.get(
            "recovery_readiness_percent"
        )

        if isinstance(recovery, (int, float)):

            self.recovery.update_value(
                f"{float(recovery):.0f}%",
                data.get(
                    "recovery_details",
                    "Live value from backend"
                )
            )

        # FAILOVER

        if data.get("failover_status") is not None:

            self.failover.update_value(
                str(data["failover_status"]).upper(),
                f'Isolation: {data.get("isolation_status", "UNKNOWN")}'
            )

        # EVENTS

        events = data.get("events", [])

        if isinstance(events, list):

            for event in events:

                if (
                        not isinstance(event, dict)
                        or not event.get("message")
                ):
                    continue

                event_key = (
                    event.get("id"),
                    event.get("timestamp"),
                    event.get("message")
                )

                if event_key in self.seen_backend_events:
                    continue

                self.seen_backend_events.add(event_key)

                severity = str(
                    event.get("severity", "INFO")
                ).upper()

                color = {
                    "ERROR": RED,
                    "CRITICAL": RED,
                    "WARNING": ORANGE,
                    "WARN": ORANGE,
                    "SUCCESS": GREEN,
                    "INFO": BLUE
                }.get(severity, MUTED)

                self.events.add_event(
                    str(event["message"]),
                    severity,
                    color
                )

        # CONNECTION STATUS

        self.system_status.setText(
            "● BACKEND CONNECTED"
        )

        self.system_status.setStyleSheet(
            f"color: {GREEN}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

    # ========================================================
    # BACKEND ERROR
    # ========================================================

    def show_backend_error(self, message):

        self.system_status.setText(
            "● BACKEND DISCONNECTED"
        )

        self.system_status.setStyleSheet(
            f"color: {RED}; font-size: 10px;"
            "font-weight: bold; border: none;"
        )

        print(
            f"[BACKEND ERROR] {message}"
        )

    # ========================================================
    # CLICK HANDLER
    # ========================================================

    def create_click_handler(self, widget):

        def handler(event):

            if event.button() == Qt.MouseButton.LeftButton:

                self.toggle_expand(widget)

            QFrame.mousePressEvent(
                widget,
                event
            )

        return handler

    # ========================================================
    # EXPAND / COLLAPSE
    # ========================================================

    def toggle_expand(self, target):

        if self.expanded_widget == target:

            target.set_expanded(False)

            for widget, row, col, rs, cs in self.layout_items:

                self.grid.addWidget(
                    widget,
                    row,
                    col,
                    rs,
                    cs
                )

                widget.show()

            self.expanded_widget = None

            return

        if self.expanded_widget is not None:

            self.expanded_widget.set_expanded(False)

        # HIDE OTHER MODULES

        for widget, *_ in self.layout_items:
            widget.hide()

        # EXPAND SELECTED MODULE

        self.expanded_widget = target

        self.grid.addWidget(
            target,
            0,
            0,
            3,
            4
        )

        target.show()

        target.set_expanded(True)


# ============================================================
# APPLICATION
# ============================================================

if __name__ == "__main__":

    app = QApplication(sys.argv)

    pg.setConfigOptions(
        antialias=True
    )

    window = QMainWindow()

    window.setWindowTitle(
        "OBSIDIAN - Resilience & Failover"
    )

    window.resize(1150, 760)

    window.setMinimumSize(
        850, 600
    )

    window.setStyleSheet(
        f"QMainWindow {{ background-color: {BG}; }}"
    )

    # CREATE DASHBOARD

    dashboard = SecurityTab()

    window.setCentralWidget(
        dashboard
    )

    # BACKEND API URL
    # Replace this with the URL provided by your friends.

    api_url = os.getenv(
        "OBSIDIAN_API_URL",
        "http://127.0.0.1:8000/api/dashboard"
    )

    # OPTIONAL AUTHENTICATION TOKEN

    api_token = os.getenv(
        "OBSIDIAN_API_TOKEN"
    )

    # START BACKEND WORKER

    backend_worker = BackendWorker(
        api_url=api_url,
        token=api_token,
        interval_seconds=2,
        parent=window
    )

    backend_worker.data_received.connect(
        dashboard.apply_backend_data
    )

    backend_worker.connection_error.connect(
        dashboard.show_backend_error
    )

    backend_worker.start()

    # WINDOWS DARK TITLE BAR

    try:

        hwnd = int(window.winId())

        value = ctypes.c_int(1)

        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            20,
            ctypes.byref(value),
            ctypes.sizeof(value)
        )

    except Exception:
        pass

    window.show()

    exit_code = app.exec()

    # STOP BACKEND THREAD CLEANLY

    backend_worker.requestInterruption()
    backend_worker.wait(6000)

    sys.exit(exit_code)
