import sys
import os
import ctypes
from collections import deque
from datetime import datetime

import requests
import pyqtgraph as pg

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QGridLayout,
    QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QProgressBar
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

SPEED_HISTORY_POINTS = 60
SPEED_AVERAGE_SAMPLES = 10
LAG_WARNING_SECONDS = 10


def number_or_none(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    return float(value)


def format_speed(mbps):
    if mbps >= 1000:
        return f"{mbps / 1000:.2f} GB/s"

    return f"{mbps:.1f} MB/s"


def format_size(mb):
    if mb >= 1024 * 1024:
        return f"{mb / (1024 * 1024):.2f} TB"

    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"

    return f"{mb:.0f} MB"


def format_duration(seconds):
    seconds = int(max(seconds, 0))

    if seconds < 60:
        return f"{seconds} s"

    if seconds < 3600:
        return f"{seconds // 60} min {seconds % 60:02d} s"

    return f"{seconds // 3600} h {(seconds % 3600) // 60:02d} min"


class BackendWorker(QThread):

    data_received = pyqtSignal(dict)
    connection_error = pyqtSignal(str)

    def __init__(self, api_url, token=None, interval_seconds=2, parent=None):
        super().__init__(parent)
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.interval_seconds = interval_seconds

    def run(self):
        headers = {"Accept": "application/json"}

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        while not self.isInterruptionRequested():
            try:
                response = requests.get(self.api_url, headers=headers, timeout=5)
                response.raise_for_status()
                data = response.json()

                if not isinstance(data, dict):
                    raise ValueError("Backend must return a JSON object.")

                self.data_received.emit(data)

            except requests.RequestException as error:
                self.connection_error.emit(str(error))

            except ValueError as error:
                self.connection_error.emit(f"Invalid JSON response: {error}")

            for _ in range(self.interval_seconds * 10):
                if self.isInterruptionRequested():
                    return
                self.msleep(100)


class DashboardCard(QFrame):

    def __init__(self):
        super().__init__()

        self.setCursor(Qt.CursorShape.PointingHandCursor)

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
    plot.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    plot.getAxis("left").setTextPen(MUTED)
    plot.getAxis("left").setPen(pg.mkPen(BORDER))


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
            f"color: {MUTED}; font-size: 11px; font-weight: bold; border: none;"
        )

        self.score_label = QLabel("-- / 5")
        self.score_label.setStyleSheet(
            f"color: {GREEN}; font-size: 17px; font-weight: bold; border: none;"
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
            self.time_series, self.risk_data, pen=pg.mkPen(GREEN, width=2)
        )

        self.threshold = pg.InfiniteLine(
            pos=5,
            angle=0,
            pen=pg.mkPen(RED, width=1.5, style=Qt.PenStyle.DashLine)
        )
        self.plot.addItem(self.threshold)

        layout.addWidget(self.plot)

        self.status = QLabel("● WAITING FOR DATA")
        self.status.setStyleSheet(
            f"color: {GREEN}; font-size: 10px; font-weight: bold; border: none;"
        )
        layout.addWidget(self.status)

    def update_score(self, score):
        if score < 0:
            return

        if score > 5:
            color, status = RED, "● CRITICAL RISK"
        elif score >= 4:
            color, status = ORANGE, "● HIGH RISK"
        elif score >= 3:
            color, status = YELLOW, "● ELEVATED RISK"
        elif score >= 2:
            color, status = BLUE, "● MODERATE RISK"
        else:
            color, status = GREEN, "● LOW RISK"

        self.score_label.setText(f"{score:.1f} / 5")
        self.score_label.setStyleSheet(
            f"color: {color}; font-size: 17px; font-weight: bold; border: none;"
        )

        self.status.setText(status)
        self.status.setStyleSheet(
            f"color: {color}; font-size: 10px; font-weight: bold; border: none;"
        )

        self.time_series.append(self.time_series[-1] + 1)
        self.risk_data.append(score)

        self.curve.setPen(pg.mkPen(color, width=2))
        self.curve.setData(self.time_series[-20:], self.risk_data[-20:])

    def set_expanded(self, expanded):
        self.plot.setMaximumHeight(16777215 if expanded else 100)

        if expanded:
            self.plot.showAxis("bottom")
        else:
            self.plot.hideAxis("bottom")


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
            f"color: {MUTED}; font-size: 11px; font-weight: bold; border: none;"
        )

        self.values = QLabel("CPU --% | IO --%")
        self.values.setStyleSheet(
            f"color: {GREEN}; font-size: 12px; font-weight: bold; border: none;"
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
            self.time_series, self.cpu_data, pen=pg.mkPen(GREEN, width=2)
        )
        self.io_curve = self.plot.plot(
            self.time_series, self.io_data, pen=pg.mkPen(BLUE, width=2)
        )

        layout.addWidget(self.plot)

        legend = QLabel("● CPU       ● DISK I/O")
        legend.setStyleSheet(f"color: {MUTED}; font-size: 10px; border: none;")
        layout.addWidget(legend)

    def update_resources(self, cpu, disk_io):
        self.values.setText(f"CPU {cpu:.0f}% | IO {disk_io:.0f}%")

        self.time_series.append(self.time_series[-1] + 1)
        self.cpu_data.append(cpu)
        self.io_data.append(disk_io)

        self.cpu_curve.setData(self.time_series[-20:], self.cpu_data[-20:])
        self.io_curve.setData(self.time_series[-20:], self.io_data[-20:])

    def set_expanded(self, expanded):
        self.plot.setMaximumHeight(16777215 if expanded else 100)

        if expanded:
            self.plot.showAxis("bottom")
        else:
            self.plot.hideAxis("bottom")


class InfoCard(DashboardCard):

    def __init__(self, title, value, subtitle="", accent=TEXT):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        self.title = QLabel(title.upper())
        self.title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold; border: none;"
        )

        self.value = QLabel(value)
        self.value.setStyleSheet(
            f"color: {accent}; font-size: 18px; font-weight: bold; border: none;"
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


class ReplicationWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        self.counter = 0
        self.time_series = deque(maxlen=SPEED_HISTORY_POINTS)
        self.speed_data = deque(maxlen=SPEED_HISTORY_POINTS)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        title = QLabel("REPLICATION ENGINE  ⤢")
        title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold; border: none;"
        )

        self.status = QLabel("● WAITING FOR DATA")
        self.status.setStyleSheet(
            f"color: {MUTED}; font-size: 13px; font-weight: bold; border: none;"
        )

        self.speed = QLabel("-- MB/s")
        self.speed.setStyleSheet(
            f"color: {TEXT}; font-size: 22px; font-weight: bold; border: none;"
        )

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {BORDER};
                border: none;
                border-radius: 4px;
            }}
            QProgressBar::chunk {{
                background-color: {BLUE};
                border-radius: 4px;
            }}
        """)
        self.progress.hide()

        self.eta = QLabel("Time remaining: --")
        self.average = QLabel("Average speed: --")
        self.lag = QLabel("Replication lag: -- sec")
        self.pending = QLabel("Pending blocks: --")

        for widget in (self.eta, self.average, self.lag, self.pending):
            widget.setStyleSheet(f"color: {MUTED}; font-size: 10px; border: none;")

        self.plot = pg.PlotWidget()
        configure_plot(self.plot, 0, 100)
        self.plot.enableAutoRange("y")
        self.plot.setLimits(yMin=0)
        self.plot.setMinimumHeight(45)
        self.plot.setMaximumHeight(60)

        self.speed_curve = self.plot.plot([], [], pen=pg.mkPen(BLUE, width=2))

        layout.addWidget(title)
        layout.addWidget(self.status)
        layout.addWidget(self.speed)
        layout.addWidget(self.progress)
        layout.addWidget(self.eta)
        layout.addWidget(self.average)
        layout.addWidget(self.lag)
        layout.addWidget(self.pending)
        layout.addWidget(self.plot, 1)

    def update_replication(
            self,
            speed,
            lag,
            pending,
            progress=None,
            remaining_mb=None,
            eta_seconds=None
    ):
        self.speed.setText(format_speed(speed))
        self.lag.setText(f"Replication lag: {lag:g} sec")
        self.pending.setText(f"Pending blocks: {pending:g}")

        if lag > LAG_WARNING_SECONDS:
            text, color = "● LAGGING", ORANGE
        elif pending > 0:
            text, color = "● SYNCING", BLUE
        else:
            text, color = "● IN SYNC", GREEN

        self.status.setText(text)
        self.status.setStyleSheet(
            f"color: {color}; font-size: 13px; font-weight: bold; border: none;"
        )

        self.counter += 1
        self.time_series.append(self.counter)
        self.speed_data.append(speed)

        recent = list(self.speed_data)[-SPEED_AVERAGE_SAMPLES:]
        self.average.setText(
            f"Average speed: {format_speed(sum(recent) / len(recent))}"
        )

        self.speed_curve.setData(list(self.time_series), list(self.speed_data))

        if progress is not None:
            progress = min(max(progress, 0.0), 100.0)
            self.progress.setValue(int(progress * 10))
            self.progress.show()
        else:
            self.progress.hide()

        if eta_seconds is None and remaining_mb is not None and speed > 0:
            eta_seconds = remaining_mb / speed

        if pending == 0:
            eta_text = "done"
        elif eta_seconds is not None:
            eta_text = f"~{format_duration(eta_seconds)}"
        else:
            eta_text = "--"

        remaining_text = (
            f" ({format_size(remaining_mb)} left)"
            if remaining_mb is not None and pending > 0 else ""
        )

        progress_text = f" · {progress:.0f}%" if progress is not None else ""

        self.eta.setText(
            f"Time remaining: {eta_text}{remaining_text}{progress_text}"
        )

    def set_expanded(self, expanded):
        self.plot.setMaximumHeight(16777215 if expanded else 60)

        if expanded:
            self.plot.showAxis("bottom")
        else:
            self.plot.hideAxis("bottom")


class EventLogWidget(DashboardCard):

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        title = QLabel("SECURITY & RECOVERY EVENTS")
        title.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold; border: none;"
        )
        layout.addWidget(title)

        self.events_layout = QVBoxLayout()
        self.events_layout.setSpacing(7)
        layout.addLayout(self.events_layout)
        layout.addStretch()

        self.add_event("Waiting for backend data...", "INFO", MUTED)

    def add_event(self, message, severity="INFO", color=MUTED):
        timestamp = datetime.now().strftime("%H:%M:%S")

        label = QLabel(f"[{timestamp}] [{severity}] {message}")
        label.setWordWrap(True)
        label.setStyleSheet(f"color: {color}; font-size: 10px; border: none;")

        self.events_layout.addWidget(label)


class SecurityTab(QWidget):

    def __init__(self):
        super().__init__()

        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(
            f"background-color: {BG}; font-family: 'Segoe UI', sans-serif;"
        )

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        header = QHBoxLayout()

        brand = QLabel("OBSIDIAN")
        brand.setStyleSheet(
            f"color: {TEXT}; font-size: 23px; font-weight: bold; border: none;"
        )

        subtitle = QLabel("RESILIENCE & FAILOVER")
        subtitle.setStyleSheet(
            f"color: {MUTED}; font-size: 10px; font-weight: bold; border: none;"
        )

        self.system_status = QLabel("● WAITING FOR BACKEND")
        self.system_status.setStyleSheet(
            f"color: {YELLOW}; font-size: 10px; font-weight: bold; border: none;"
        )

        header.addWidget(brand)
        header.addSpacing(14)
        header.addWidget(subtitle)
        header.addStretch()
        header.addWidget(self.system_status)
        main_layout.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        content = QWidget()
        content.setStyleSheet(f"background-color: {BG};")

        self.grid = QGridLayout(content)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setSpacing(12)

        for col in range(4):
            self.grid.setColumnStretch(col, 1)

        for row in range(3):
            self.grid.setRowStretch(row, 1)

        scroll.setWidget(content)
        main_layout.addWidget(scroll)

        self.expanded_widget = None
        self.seen_backend_events = set()

        self.risk_module = CompactRiskWidget()
        self.resources_module = CompactResourcesWidget()

        self.primary = InfoCard(
            "Primary Server", "WAITING", "Waiting for backend data", GREEN
        )
        self.secondary = InfoCard(
            "Secondary Server", "WAITING", "Waiting for backend data", BLUE
        )

        self.replication = ReplicationWidget()

        self.integrity = InfoCard(
            "Data Integrity", "WAITING", "Waiting for backend data", GREEN
        )
        self.recovery = InfoCard(
            "Recovery Readiness", "--", "Waiting for backend data", GREEN
        )
        self.failover = InfoCard(
            "Failover Status", "WAITING", "Waiting for backend data", GREEN
        )

        self.events = EventLogWidget()

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
            self.grid.addWidget(widget, row, col, rs, cs)
            widget.mousePressEvent = self.create_click_handler(widget)

    def apply_backend_data(self, data):
        risk = data.get("risk_score")

        if isinstance(risk, (int, float)):
            self.risk_module.update_score(float(risk))

        cpu = data.get("cpu_percent")
        disk_io = data.get("disk_io_percent")

        if isinstance(cpu, (int, float)) and isinstance(disk_io, (int, float)):
            self.resources_module.update_resources(float(cpu), float(disk_io))

        if data.get("primary_status") is not None:
            self.primary.update_value(
                str(data["primary_status"]).upper(),
                data.get("primary_details", "Live status from backend")
            )

        if data.get("secondary_status") is not None:
            self.secondary.update_value(
                str(data["secondary_status"]).upper(),
                data.get("secondary_details", "Live status from backend")
            )

        speed = number_or_none(data.get("replication_speed_mbps"))
        lag = number_or_none(data.get("replication_lag_seconds"))
        pending = number_or_none(data.get("pending_blocks"))

        if speed is not None and lag is not None and pending is not None:
            self.replication.update_replication(
                speed,
                lag,
                pending,
                number_or_none(data.get("replication_progress_percent")),
                number_or_none(data.get("replication_remaining_mb")),
                number_or_none(data.get("replication_eta_seconds"))
            )

        if data.get("integrity_status") is not None:
            self.integrity.update_value(
                str(data["integrity_status"]).upper(),
                data.get("integrity_details", "Live status from backend")
            )

        recovery = data.get("recovery_readiness_percent")

        if isinstance(recovery, (int, float)):
            self.recovery.update_value(
                f"{float(recovery):.0f}%",
                data.get("recovery_details", "Live value from backend")
            )

        if data.get("failover_status") is not None:
            self.failover.update_value(
                str(data["failover_status"]).upper(),
                f'Isolation: {data.get("isolation_status", "UNKNOWN")}'
            )

        events = data.get("events", [])

        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict) or not event.get("message"):
                    continue

                event_key = (
                    event.get("id"),
                    event.get("timestamp"),
                    event.get("message")
                )

                if event_key in self.seen_backend_events:
                    continue

                self.seen_backend_events.add(event_key)

                severity = str(event.get("severity", "INFO")).upper()

                color = {
                    "ERROR": RED,
                    "CRITICAL": RED,
                    "WARNING": ORANGE,
                    "WARN": ORANGE,
                    "SUCCESS": GREEN,
                    "INFO": BLUE
                }.get(severity, MUTED)

                self.events.add_event(str(event["message"]), severity, color)

        self.system_status.setText("● BACKEND CONNECTED")
        self.system_status.setStyleSheet(
            f"color: {GREEN}; font-size: 10px; font-weight: bold; border: none;"
        )

    def show_backend_error(self, message):
        self.system_status.setText("● BACKEND DISCONNECTED")
        self.system_status.setStyleSheet(
            f"color: {RED}; font-size: 10px; font-weight: bold; border: none;"
        )
        print(f"[BACKEND ERROR] {message}")

    def create_click_handler(self, widget):

        def handler(event):
            if event.button() == Qt.MouseButton.LeftButton:
                self.toggle_expand(widget)

            QFrame.mousePressEvent(widget, event)

        return handler

    def toggle_expand(self, target):
        if self.expanded_widget == target:
            target.set_expanded(False)

            for widget, row, col, rs, cs in self.layout_items:
                self.grid.addWidget(widget, row, col, rs, cs)
                widget.show()

            self.expanded_widget = None
            return

        if self.expanded_widget is not None:
            self.expanded_widget.set_expanded(False)

        for widget, *_ in self.layout_items:
            widget.hide()

        self.expanded_widget = target
        self.grid.addWidget(target, 0, 0, 3, 4)
        target.show()
        target.set_expanded(True)


if __name__ == "__main__":

    app = QApplication(sys.argv)

    pg.setConfigOptions(antialias=True)

    window = QMainWindow()
    window.setWindowTitle("OBSIDIAN - Resilience & Failover")
    window.resize(1150, 760)
    window.setMinimumSize(850, 600)
    window.setStyleSheet(f"QMainWindow {{ background-color: {BG}; }}")

    dashboard = SecurityTab()
    window.setCentralWidget(dashboard)

    api_url = os.getenv("OBSIDIAN_API_URL", "http://127.0.0.1:8000/api/dashboard")
    api_token = os.getenv("OBSIDIAN_API_TOKEN")

    backend_worker = BackendWorker(
        api_url=api_url,
        token=api_token,
        interval_seconds=2,
        parent=window
    )

    backend_worker.data_received.connect(dashboard.apply_backend_data)
    backend_worker.connection_error.connect(dashboard.show_backend_error)
    backend_worker.start()

    try:
        hwnd = int(window.winId())
        value = ctypes.c_int(1)
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 20, ctypes.byref(value), ctypes.sizeof(value)
        )
    except Exception:
        pass

    window.show()

    exit_code = app.exec()

    backend_worker.requestInterruption()
    backend_worker.wait(6000)

    sys.exit(exit_code)
