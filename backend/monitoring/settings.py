import json
import os
import time

import config

CUT_CHOICES = config.THREAT_LEVELS[1:] + ["OFF"]
COMMAND_MAX_AGE = 120      # seconds; older commands are ignored


def _write(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def threat_level(score: float) -> str:
    level = "LOW"
    for name in config.THREAT_LEVELS[1:]:
        if score >= config.LEVEL_THRESHOLDS[name]:
            level = name
    return level


def get_cut_level() -> str:
    try:
        return json.loads(config.SETTINGS_PATH.read_text()).get("cut_level", config.DEFAULT_CUT_LEVEL)
    except (OSError, ValueError):
        return config.DEFAULT_CUT_LEVEL


def set_cut_level(level: str) -> str:
    if level not in CUT_CHOICES:
        raise ValueError(f"level must be one of {CUT_CHOICES}")
    _write(config.SETTINGS_PATH, {"cut_level": level})
    return level


def should_cut(level: str, cut_level: str) -> bool:
    if cut_level == "OFF":
        return False
    order = config.THREAT_LEVELS
    return order.index(level) >= order.index(cut_level)


# --- command channel: dashboard (API process) -> live IDS process ----------
def send_command(action: str) -> None:
    if action not in ("cut", "restore"):
        raise ValueError("action must be 'cut' or 'restore'")
    _write(config.COMMAND_PATH, {"action": action, "ts": time.time()})


def take_command():
    """Read and delete a pending command. Returns 'cut', 'restore' or None."""
    try:
        cmd = json.loads(config.COMMAND_PATH.read_text())
    except (OSError, ValueError):
        return None
    try:
        config.COMMAND_PATH.unlink()
    except OSError:
        pass
    if time.time() - float(cmd.get("ts", 0)) > COMMAND_MAX_AGE:
        return None
    return cmd.get("action")