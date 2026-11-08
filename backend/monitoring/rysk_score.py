class RiskEngine:
    ELEVATED, BLOCK, QUARANTINE = 40, 60, 90

    def __init__(self, ip_decay: float = 8, host_decay: float = 20):
        self.ip_decay, self.host_decay = ip_decay, host_decay
        self.ip_scores = {}
        self.host_score = 0.0
        self._fim_sig = None

    def _action(self, score: float, multi_vector: bool) -> str:
        if score >= self.QUARANTINE and multi_vector:
            return "QUARANTINE"
        if score >= self.BLOCK:
            return "BLOCK_IP"
        if score >= self.ELEVATED:
            return "ELEVATED_SCAN"
        return "PASS"

    def update(self, detections: list, fim_changes=None) -> dict:
        seen = set()
        for d in detections:
            delta = min(70, 15 + 30 * d["severity"] + 25 * len(d["rule_hits"]))
            self.ip_scores[d["src"]] = min(100, self.ip_scores.get(d["src"], 0) + delta)
            seen.add(d["src"])

        for ip in list(self.ip_scores):            # quiet sources cool down
            if ip not in seen:
                self.ip_scores[ip] -= self.ip_decay
                if self.ip_scores[ip] <= 0:
                    del self.ip_scores[ip]

        if fim_changes is not None:
            sig = frozenset((c["path"], c["change"]) for c in fim_changes)
            if fim_changes and sig != self._fim_sig:     # NEW breach -> jump
                self.host_score = min(100, self.host_score + 60)
            else:                                        # clean or same old breach -> cool down
                self.host_score = max(0, self.host_score - self.host_decay)
            self._fim_sig = sig                          # inside the if, so sig always exists

        strong = {d["src"] for d in detections if d["rule_hits"] or d["severity"] >= 0.3}
        per_ip = {}
        for ip, s in self.ip_scores.items():
            multi = ip in strong and self.host_score > 0
            combined = min(100, s + (0.5 * self.host_score if multi else 0))
            per_ip[ip] = {"score": round(combined, 1), "action": self._action(combined, multi)}

        order = ["PASS", "ELEVATED_SCAN", "BLOCK_IP", "QUARANTINE"]
        overall_action = max((v["action"] for v in per_ip.values()),
                             key=order.index, default="PASS")
        overall = max([self.host_score] + [v["score"] for v in per_ip.values()])
        if overall_action == "PASS" and self.host_score >= self.ELEVATED:
            overall_action = "ELEVATED_SCAN"
        return {"overall": overall, "action": overall_action,
                "host_score": self.host_score, "per_ip": per_ip}