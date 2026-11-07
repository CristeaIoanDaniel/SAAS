
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QGridLayout
)
from PyQt6.QtCore import Qt, QRectF, QPointF
from PyQt6.QtGui import (
    QPainter, QPen, QColor, QFont, QPolygonF
)
import math

DEMO = {
    "risk": 38,
    "events": 12,
    "high_priority": 3,
    "integrity": 98.6,
    "history": [20, 28, 23, 35, 31, 45, 38, 42, 34, 38, 30, 38],
    "suspicious": 24,
    "blocked": 18,
    "critical": 3,
}


COLORS = {
    "green": "#35c987",
    "yellow": "#f0c44f",
    "orange": "#f28c45",
    "red": "#ed6262",
    "blue": "#55aaff",
    "gray": "#89919b",
}


def panel():
    box = QFrame()
    box.setStyleSheet("""
        QFrame {
            background-color: #15191d;
            border: 1px solid #292f35;
            border-radius: 10px;
        }
    """)
    return box


def heading(text):
    label = QLabel(text)
    label.setStyleSheet("""
        color: #aeb6bf;
        font-size: 11px;
        font-weight: bold;
        border: none;
    """)
    return label


class RiskGauge(QWidget):
    def __init__(self, value):
        super().__init__()
        self.value = value
        self.setFixedSize(270, 220)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        cx = self.width() / 2
        cy = 112
        radius = 82

        rect = QRectF(
            cx - radius, cy - radius,
            radius * 2, radius * 2
        )

        zones = [
            (0, 25, COLORS["green"]),
            (25, 50, COLORS["yellow"]),
            (50, 75, COLORS["orange"]),
            (75, 100, COLORS["red"]),
        ]

        pen = QPen()
        pen.setWidth(15)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)

        for start, end, color in zones:
            pen.setColor(QColor(color))
            p.setPen(pen)
            p.drawArc(
                rect,
                int((150 - start * 2.4) * 16),
                int(-(end - start) * 2.4 * 16)
            )

        angle = math.radians(150 - self.value * 2.4)
        length = 59
        x = cx + math.cos(angle) * length
        y = cy - math.sin(angle) * length

        needle = QPen(QColor("#ffffff"))
        needle.setWidth(3)
        needle.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(needle)
        p.drawLine(QPointF(cx, cy), QPointF(x, y))

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("#ffffff"))
        p.drawEllipse(QPointF(cx, cy), 6, 6)

        p.setPen(QColor("#ffffff"))
        p.setFont(QFont("Helvetica", 27, QFont.Weight.Bold))
        p.drawText(
            QRectF(70, 112, 130, 42),
            Qt.AlignmentFlag.AlignCenter,
            f"{self.value}%"
        )

        p.setPen(QColor(COLORS["yellow"]))
        p.setFont(QFont("Helvetica", 10, QFont.Weight.Bold))
        p.drawText(
            QRectF(65, 151, 140, 22),
            Qt.AlignmentFlag.AlignCenter,
            "MODERATE RISK"
        )

        p.setPen(QColor(COLORS["gray"]))
        p.setFont(QFont("Helvetica", 8))
        p.drawText(
            QRectF(15, 195, 240, 16),
            Qt.AlignmentFlag.AlignCenter,
            "LOW                 HIGH"
        )

        p.end()


class MetricCard(QFrame):
    def __init__(self, name, value, detail, color):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #1a1f24;
                border: 1px solid #292f35;
                border-radius: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(4)

        name_label = heading(name)
        value_label = QLabel(value)
        value_label.setStyleSheet(
            f"color: {color}; font-size: 23px; "
            "font-weight: bold; border: none;"
        )

        detail_label = QLabel(detail)
        detail_label.setStyleSheet(
            "color: #89919b; font-size: 10px; border: none;"
        )

        layout.addWidget(name_label)
        layout.addWidget(value_label)
        layout.addWidget(detail_label)


class HistoryChart(QWidget):
    def __init__(self, values):
        super().__init__()
        self.values = values
        self.setMinimumHeight(105)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        left, right, top, bottom = 12, 12, 12, 18

        # Grid lines
        grid_pen = QPen(QColor("#30373e"))
        grid_pen.setWidth(1)
        p.setPen(grid_pen)

        for i in range(4):
            y = top + i * (h - top - bottom) / 3
            p.drawLine(
                int(left), int(y),
                int(w - right), int(y)
            )

        points = []
        for i, value in enumerate(self.values):
            x = left + i * (w - left - right) / (
                len(self.values) - 1
            )
            y = h - bottom - value * (h - top - bottom) / 100
            points.append(QPointF(x, y))

        line_pen = QPen(QColor(COLORS["green"]))
        line_pen.setWidth(2)
        p.setPen(line_pen)

        for i in range(len(points) - 1):
            p.drawLine(points[i], points[i + 1])

        p.setPen(QColor(COLORS["gray"]))
        p.setFont(QFont("Helvetica", 8))
        p.drawText(2, h - 2, "12 readings")

        p.end()


class ActivityChart(QWidget):
    def __init__(self, values):
        super().__init__()
        self.values = values
        self.setMinimumHeight(105)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        labels = ["Suspicious", "Blocked", "Critical"]
        colors = [
            COLORS["yellow"],
            COLORS["green"],
            COLORS["red"]
        ]

        max_value = max(max(self.values), 1)
        bar_width = 13
        row_height = 29

        for i, value in enumerate(self.values):
            y = 8 + i * row_height

            p.setPen(QColor("#aeb6bf"))
            p.setFont(QFont("Helvetica", 8))
            p.drawText(2, y + 10, labels[i])

            start = 85
            available = max(20, self.width() - 125)
            bar_length = available * value / max_value

            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor("#30373e"))
            p.drawRoundedRect(
                start, y, available, bar_width, 4, 4
            )

            p.setBrush(QColor(colors[i]))
            p.drawRoundedRect(
                start, y, int(bar_length), bar_width, 4, 4
            )

            p.setPen(QColor("#ffffff"))
            p.drawText(
                start + available + 7, y + 11, str(value)
            )

        p.end()


class RiskCenterPage(QWidget):
    def __init__(self):
        super().__init__()

        self.setStyleSheet("""
            QWidget {
                background-color: #0b0d0e;
                color: #e5e7eb;
                font-family: Helvetica;
            }
        """)

        main = QVBoxLayout(self)
        main.setContentsMargins(20, 16, 20, 16)
        main.setSpacing(10)

        header = QHBoxLayout()

        title = QLabel("RISK CENTER")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: white;"
        )

        demo = QLabel("● DEMO MODE")
        demo.setStyleSheet(
            f"color: {COLORS['yellow']}; font-size: 10px;"
            "font-weight: bold;"
        )

        header.addWidget(title)
        header.addStretch()
        header.addWidget(demo)
        main.addLayout(header)

        top = QHBoxLayout()
        top.setSpacing(12)

        gauge_panel = panel()
        gauge_layout = QVBoxLayout(gauge_panel)
        gauge_layout.setContentsMargins(8, 8, 8, 5)
        gauge_layout.setSpacing(0)
        gauge_layout.addWidget(
            heading("OVERALL ATTACK RISK"),
            alignment=Qt.AlignmentFlag.AlignCenter
        )
        gauge_layout.addWidget(
            RiskGauge(DEMO["risk"]),
            alignment=Qt.AlignmentFlag.AlignCenter
        )

        top.addWidget(gauge_panel, 1)

        metrics = QWidget()
        metrics_layout = QGridLayout(metrics)
        metrics_layout.setContentsMargins(0, 0, 0, 0)
        metrics_layout.setSpacing(10)

        metrics_layout.addWidget(
            MetricCard(
                "SECURITY EVENTS",
                str(DEMO["events"]),
                f"{DEMO['high_priority']} high priority",
                COLORS["orange"]
            ), 0, 0
        )

        metrics_layout.addWidget(
            MetricCard(
                "SYSTEM INTEGRITY",
                f"{DEMO['integrity']}%",
                "Verification score",
                COLORS["blue"]
            ), 0, 1
        )

        metrics_layout.addWidget(
            MetricCard(
                "BLOCKED ATTEMPTS",
                str(DEMO["blocked"]),
                "Demo count",
                COLORS["green"]
            ), 1, 0
        )

        metrics_layout.addWidget(
            MetricCard(
                "CRITICAL ALERTS",
                str(DEMO["critical"]),
                "Requires attention",
                COLORS["red"]
            ), 1, 1
        )

        top.addWidget(metrics, 1)
        main.addLayout(top, 3)

        charts = QHBoxLayout()
        charts.setSpacing(12)

        history_panel = panel()
        history_layout = QVBoxLayout(history_panel)
        history_layout.setContentsMargins(12, 10, 12, 8)
        history_layout.addWidget(heading("RISK HISTORY"))
        history_layout.addWidget(HistoryChart(DEMO["history"]))

        activity_panel = panel()
        activity_layout = QVBoxLayout(activity_panel)
        activity_layout.setContentsMargins(12, 10, 12, 8)
        activity_layout.addWidget(heading("THREAT ACTIVITY"))
        activity_layout.addWidget(
            ActivityChart([
                DEMO["suspicious"],
                DEMO["blocked"],
                DEMO["critical"]
            ])
        )

        charts.addWidget(history_panel)
        charts.addWidget(activity_panel)
        main.addLayout(charts, 2)

        footer = QLabel(
            "DEMONSTRATION VALUES ONLY  •  NOT CONNECTED TO SERVERS"
        )
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet(
            "color: #68717a; font-size: 9px; padding: 3px;"
        )
        main.addWidget(footer)
