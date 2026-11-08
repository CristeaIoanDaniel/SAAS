import json
import os

import config
import security
import settings
from events import bus
from rysk_score import RiskEngine


class Pipeline:
    def __init__(self, ids, resp, log, tracker, sender=None, simulated=False):
        self.ids, self.resp, self.log, self.tracker = ids, resp, log, tracker
        self.sender, self.simulated = sender, simulated
        self.risk = RiskEngine()
        self.last_status = self._base_status()

    # -- helpers -----------------------------------------------------------
    @property
    def cut(self) -> bool:
        return bool(self.resp.quarantined or self.resp.adapters_down)

    def _base_status(self) -> dict:
        return {"type": "window", "flagged": 0, "overall": 0, "host_score": 0, "action": "PASS",
                "threat_level": "LOW", "cut_level": settings.get_cut_level(), "per_ip": {},
                "network_cut": False, "simulated": self.simulated, "dry_run": self.resp.dry_run}

    def _out(self, rec):
        rec = {**rec, "simulated": self.simulated}
        bus.publish(rec)
        if self.sender:
            self.sender.send(rec)

    def _publish_status(self, status: dict):
        self.last_status = status
        bus.publish(status)
        if not self.simulated:               # lets the API (separate process) mirror live state
            tmp = config.STATUS_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(status, default=security.json_default))
            os.replace(tmp, config.STATUS_PATH)

    def _cut(self, level, cut_level, report=None, manual=False):
        self._out(self.log.append({"type": "quarantine", "manual": manual, "report": report,
                                   "threat_level": level, "cut_level": cut_level,
                                   "dry_run": self.resp.dry_run}))
        if self.sender:
            self.sender.flush()              # alert out BEFORE the network dies
        self.resp.kill_switch()
        self._out(self.log.append({"type": "network_cut", "manual": manual,
                                   "dry_run": self.resp.dry_run,
                                   "adapters": config.NETWORK_ADAPTERS if config.HARD_CUT else []}))

    # -- manual control (from the dashboard) -------------------------------
    def manual_cut(self):
        if self.cut:
            return
        self._cut("SEVERE", settings.get_cut_level(), manual=True)
        self._publish_status({**self.last_status, "threat_level": "SEVERE",
                              "network_cut": self.cut, "dry_run": self.resp.dry_run})

    def manual_restore(self):
        self.resp.restore_network()
        self.risk = RiskEngine()             # otherwise the old score would re-cut immediately
        self._out(self.log.append({"type": "network_restored", "dry_run": self.resp.dry_run}))
        self._publish_status({**self._base_status(), "network_cut": self.cut})

    # -- main per-window processing ----------------------------------------
    def process(self, pkts, window, fim_changes=None, whitelist=()):
        dets = self.ids.analyze(pkts, window, whitelist)
        report = self.risk.update(dets, fim_changes)

        for d in dets:
            info = report["per_ip"].get(d["src"], {"score": 0, "action": "PASS"})
            rec = self.log.append({"type": "network_anomaly", **d,
                                   "risk": info["score"], "action": info["action"]})
            self.tracker.record(d, info["score"], info["action"])
            self._out(rec)

        for ip, info in report["per_ip"].items():
            if info["action"] in ("BLOCK_IP", "QUARANTINE") and self.resp.block_ip(ip):
                self._out(self.log.append({"type": "response", "action": "block_ip",
                                           "ip": ip, "dry_run": self.resp.dry_run}))

        level = settings.threat_level(report["overall"])
        cut_level = settings.get_cut_level()
        if settings.should_cut(level, cut_level) and not self.cut:
            self._cut(level, cut_level, report)

        self._publish_status({"type": "window", "flagged": len(dets), "overall": report["overall"],
                              "host_score": report["host_score"], "action": report["action"],
                              "threat_level": level, "cut_level": cut_level,
                              "per_ip": report["per_ip"], "network_cut": self.cut,
                              "simulated": self.simulated, "dry_run": self.resp.dry_run})
        return report, dets