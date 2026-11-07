import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import config
import security

GENESIS = "0" * 64


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, default=security.json_default)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class IncidentLog:
    def __init__(self, path=config.INCIDENT_LOG):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.prev_hash = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]
        return json.loads(lines[-1]).get("hash", GENESIS) if lines else GENESIS

    def append(self, event: dict) -> dict:
        with self._lock:
            now = time.time()
            rec = {"ts": round(now, 3), "iso": _iso(now), **event, "prev": self.prev_hash}
            rec["hash"] = hashlib.sha256(_dumps(rec).encode()).hexdigest()
            rec["sig"] = security.sign(rec["hash"].encode())
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(_dumps(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.prev_hash = rec["hash"]
            return rec

    @staticmethod
    def verify(path=config.INCIDENT_LOG):
        path = Path(path)
        if not path.exists():
            return True, "no log yet"
        prev, n = GENESIS, 0
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                try:
                    rec = json.loads(line)
                except ValueError:
                    return False, f"line {n}: not valid JSON"
                digest, sig = rec.pop("hash", None), rec.pop("sig", None)
                if rec.get("prev") != prev:
                    return False, f"line {n}: chain broken (record removed, added or reordered)"
                if hashlib.sha256(_dumps(rec).encode()).hexdigest() != digest:
                    return False, f"line {n}: record content was modified"
                if not security.verify((digest or "").encode(), sig):
                    return False, f"line {n}: signature invalid"
                prev = digest
        return True, f"{n} records verified, chain intact"


class AttackerTracker:
    def __init__(self, path=config.ATTACKER_DB):
        self.path = Path(path)
        self.profiles = json.loads(self.path.read_text()) if self.path.exists() else {}

    def record(self, det: dict, risk: float, action: str):
        now, ip = time.time(), det["src"]
        p = self.profiles.setdefault(ip, {
            "first_seen": now, "last_seen": now, "windows_flagged": 0,
            "labels": {}, "peak_risk": 0, "last_action": "PASS", "episodes": []})
        p["last_seen"] = now
        p["windows_flagged"] += 1
        p["peak_risk"] = max(p["peak_risk"], risk)
        p["last_action"] = action
        for lab in det["label"].split("+"):
            p["labels"][lab] = p["labels"].get(lab, 0) + 1

        ep = p["episodes"][-1] if p["episodes"] else None
        if ep and now - ep["end"] <= config.EPISODE_GAP:      # same attack continues
            ep["end"] = now
            ep["windows"] += 1
            ep["peak_risk"] = max(ep["peak_risk"], risk)
            ep["packets"] += det["packets"]
            ep["labels"] = sorted(set(ep["labels"]) | set(det["label"].split("+")))
            ep["ports"] = sorted(set(ep["ports"]) | set(det["ports"]))[:50]
        else:                                                  # a new attack episode
            p["episodes"].append({
                "start": now, "end": now, "windows": 1, "peak_risk": risk,
                "packets": det["packets"], "labels": det["label"].split("+"),
                "ports": list(det["ports"])[:50]})
        self._save()

    def _save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.profiles, indent=1))
        os.replace(tmp, self.path)

    def report(self) -> str:
        if not self.profiles:
            return "No attackers recorded yet."
        out = []
        for ip, p in sorted(self.profiles.items(), key=lambda kv: -kv[1]["peak_risk"]):
            out += [f"=== {ip} ===",
                    f"  first seen : {_iso(p['first_seen'])}",
                    f"  last seen  : {_iso(p['last_seen'])}",
                    f"  windows flagged: {p['windows_flagged']} | peak risk: {p['peak_risk']} "
                    f"| last action: {p['last_action']}",
                    f"  attack types: {p['labels']}",
                    "  episodes:"]
            for i, ep in enumerate(p["episodes"], 1):
                dur = max(1, int(ep["end"] - ep["start"]))
                out.append(f"    #{i} {_iso(ep['start'])} -> {_iso(ep['end'])} ({dur}s, "
                           f"{ep['windows']} windows, {ep['packets']} pkts) "
                           f"{ep['labels']} ports={ep['ports'][:10]}")
            out.append("")
        return "\n".join(out)