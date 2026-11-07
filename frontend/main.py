
import sys

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QTabWidget,
)
from pages.simulation import SimulationTab
from pages.home import HomePage
from pages.admin import AdminTab
from pages.risk_center import RiskCenterPage


class ObsidianApp(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("OBSIDIAN")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setMovable(False)
        self.tabs.tabBar().setExpanding(True)
        self.tabs.tabBar().setUsesScrollButtons(False)

        self.home_tab = HomePage()
        self.simulation_tab = SimulationTab()
        self.risk_tab = RiskCenterPage()
        self.admin_tab = AdminTab()

        self.tabs.addTab(self.home_tab, "HOME")
        self.tabs.addTab(self.simulation_tab, "SIMULATION")
        self.tabs.addTab(self.risk_tab, "RISK CENTER")
        self.tabs.addTab(self.admin_tab, "ADMIN")

        self.setCentralWidget(self.tabs)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #080808;
            }

            QTabWidget::pane {
                border: none;
                background-color: #080808;
            }

           QTabBar::tab {
                background-color: #080808;
                color: #929292;
                min-width: 0px;
                padding: 18px 10px;
                margin: 0px;
                border: none;
                border-bottom: 2px solid transparent;
                font-size: 13px;
                font-weight: 600;
            }

            QTabBar::tab:selected {
                color: #F5F5F5;
                border-bottom: 2px solid #00A878;
            }

            QTabBar::tab:hover {
                color: #FFFFFF;
            }
        """)

    def closeEvent(self, event):
        self.home_tab.stop_backend()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ObsidianApp()
    window.show()

    sys.exit(app.exec())
