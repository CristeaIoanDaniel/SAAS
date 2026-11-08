
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = DATA_DIR / "ids_model.joblib"
CLASSIFIER_PATH = DATA_DIR / "attack_classifier.joblib"
KEY_PATH = DATA_DIR / "hmac.key"
FIM_BASELINE_PATH = DATA_DIR / "fim_baseline.json"
INCIDENT_LOG = LOG_DIR / "incidents.jsonl"
ATTACKER_DB = LOG_DIR / "attackers.json"
SPOOL_PATH = LOG_DIR / "alert_spool.jsonl"
WINDOW_SECONDS = 5
MIN_PACKETS = 3
TARGET_FPR = 0.005
CLASSIFIER_THRESHOLD = 0.7
FIM_INTERVAL = 30
EPISODE_GAP = 30
PORT_SCAN_PORTS = 20
SYN_FLOOD_PKTS = 100
SYN_FLOOD_RATIO = 0.8
SWEEP_HOSTS = 20
WATCHED_PATHS = [BASE_DIR]
WATCH_EXTENSIONS = {".py"}
FIM_EXCLUDE_DIRS = {"data", "logs", "__pycache__", ".venv", ".git"}
WHITELIST = {"127.0.0.1"}
COLLECTOR_URL = os.environ.get("IDS_COLLECTOR_URL", "")
COLLECTOR_CA = os.environ.get("IDS_COLLECTOR_CA", "")
NETWORK_ADAPTERS = ["Wi-Fi", "Ethernet", "Ethernet 2"]   # names from: netsh interface show interface
STATUS_PATH = LOG_DIR / "live_status.json"
HARD_CUT = True
SETTINGS_PATH = DATA_DIR / "settings.json"
THREAT_LEVELS = ["LOW", "ELEVATED", "HIGH", "SEVERE"]
LEVEL_THRESHOLDS = {"ELEVATED": 40, "HIGH": 60, "SEVERE": 90}   # overall risk score
DEFAULT_CUT_LEVEL = "SEVERE"
COMMAND_PATH = DATA_DIR / "command.json"