"""
packet_monitor.py - network capture + hybrid anomaly detection.

Detection is done PER SOURCE IP (an attacker is invisible once all traffic is
averaged together). Two layers work together:
  1. Rules       -> known attack shapes (port scan, SYN flood, host sweep)
  2. Isolation Forest -> anything statistically unusual versus your own baseline
"""
import random
import threading
import time
from collections import Counter, defaultdict, deque

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler

import config
import security

FEATURE_NAMES = [
    "pkt_count",          # packets from this source in the window
    "unique_ports",       # distinct destination ports (all packets)
    "unsolicited_ports",  # distinct ports hit by TCP packets WITHOUT the ACK flag
    "unique_dsts",        # distinct destination hosts
    "avg_size",
    "std_size",
    "syn_ratio",          # bare SYN (flags == 'S') / packets  -> SYN flood signal
    "rst_ratio",
    "bytes_per_sec",
    "port_entropy",       # high entropy = spraying many ports (scan)
]


# --------------------------------------------------------------------------
# Feature extraction
# --------------------------------------------------------------------------
def _entropy(values) -> float:
    counts = np.array(list(Counter(values).values()), dtype=float)
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def extract_features(group, window: float) -> list:
    """group = packets from ONE source IP. Returns a vector in FEATURE_NAMES order."""
    n = len(group)
    sizes = np.array([p["size"] for p in group], dtype=float)
    dports = [p["dport"] for p in group]
    unsolicited = {p["dport"] for p in group
                   if p.get("proto") == "TCP" and "A" not in p["flags"]}
    syn = sum(1 for p in group if p["flags"] == "S")
    rst = sum(1 for p in group if "R" in p["flags"])
    return [
        n,
        len(set(dports)),
        len(unsolicited),
        len({p["dst"] for p in group}),
        float(sizes.mean()),
        float(sizes.std()),
        syn / n,
        rst / n,
        float(sizes.sum() / window),
        _entropy(dports),
        ]


def group_by_source(pkts) -> dict:
    groups = defaultdict(list)
    for p in pkts:
        groups[p["src"]].append(p)
    return groups


def iter_sources(pkts, window, whitelist=()):
    """Yield (src_ip, packets, feature_vector) for every source worth analysing."""
    for src, group in group_by_source(pkts).items():
        if src in whitelist or len(group) < config.MIN_PACKETS:
            continue
        yield src, group, extract_features(group, window)


# --------------------------------------------------------------------------
# Rule layer (known attack shapes)
# --------------------------------------------------------------------------
def rule_hits(f: dict) -> list:
    hits = []
    if f["unsolicited_ports"] >= config.PORT_SCAN_PORTS:
        hits.append("port_scan")
    # flood = lots of bare SYNs concentrated on FEW ports (a scan sprays many ports)
    if (f["pkt_count"] >= config.SYN_FLOOD_PKTS and f["syn_ratio"] >= config.SYN_FLOOD_RATIO
            and f["unsolicited_ports"] < config.PORT_SCAN_PORTS):
        hits.append("syn_flood")
    if f["unique_dsts"] >= config.SWEEP_HOSTS:
        hits.append("host_sweep")
    return hits



# --------------------------------------------------------------------------
# Supervised layer (learns from LABELED normal + attack examples)
# --------------------------------------------------------------------------
class AttackClassifier:
    """Random Forest that outputs P(attack) for a source's feature vector."""

    def __init__(self):
        self.model = None

    def train(self, rows, labels):
        X, y = np.asarray(rows, dtype=float), np.asarray(labels, dtype=int)
        if y.sum() < 20 or (len(y) - y.sum()) < 20:
            raise ValueError("Need at least 20 attack AND 20 normal samples.")
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
        check = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                       random_state=42).fit(Xtr, ytr)
        print("[*] Accuracy on held-out data the model never saw during training:")
        print(classification_report(yte, check.predict(Xte),
                                    target_names=["normal", "attack"], digits=3))
        # final model uses ALL the data
        self.model = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                            random_state=42).fit(X, y)

    def proba(self, vec) -> float:
        return float(self.model.predict_proba([vec])[0][1])

    def save(self, path=config.CLASSIFIER_PATH):
        joblib.dump({"model": self.model, "features": FEATURE_NAMES}, path)
        security.sign_file(path)
        print(f"[+] Attack classifier saved and signed: {path}")

    @classmethod
    def load(cls, path=config.CLASSIFIER_PATH):
        if not security.verify_file(path):
            raise RuntimeError("Classifier missing or signature invalid.")
        blob = joblib.load(path)
        if blob["features"] != FEATURE_NAMES:
            raise RuntimeError("Classifier was trained with different features - retrain.")
        c = cls()
        c.model = blob["model"]
        c.model.set_params(n_jobs=1)
        return c

# --------------------------------------------------------------------------
# ML layer
# --------------------------------------------------------------------------
class NetworkIDS:
    def __init__(self, target_fpr: float = config.TARGET_FPR):
        self.target_fpr = target_fpr
        self.model = None
        self.threshold = None
        self.clf = None          # optional supervised AttackClassifier

    @property
    def is_trained(self) -> bool:
        return self.model is not None

    def train(self, rows):
        """rows: list of feature vectors from NORMAL traffic (one per source per window)."""
        X = np.asarray(rows, dtype=float)
        if len(X) < 100:
            raise ValueError(f"Only {len(X)} samples - capture more normal traffic (need 100+).")
        # RobustScaler: a few huge values (downloads) won't squash everything else
        self.model = make_pipeline(
            RobustScaler(),
            IsolationForest(n_estimators=300, contamination="auto", random_state=42),
        )
        self.model.fit(X)
        scores = self.model.score_samples(X)
        # Threshold calibrated so only ~target_fpr of NORMAL windows would be flagged
        self.threshold = float(np.quantile(scores, self.target_fpr))
        print(f"[+] Trained on {len(X)} samples | anomaly threshold = {self.threshold:.4f}")

    def _severity(self, score: float) -> float:
        """Map the raw score to 0..1 (0 = at threshold, 1 = maximally abnormal)."""
        span = max(0.05, 1.0 + self.threshold)
        return float(np.clip((self.threshold - score) / span, 0.0, 1.0))

    def analyze(self, pkts, window: float, whitelist=()) -> list:
        """Returns one detection dict per suspicious source IP."""
        detections = []
        for src, group, vec in iter_sources(pkts, window, whitelist):
            feats = dict(zip(FEATURE_NAMES, vec))
            hits = rule_hits(feats)
            ml_score, ml_flag, severity = None, False, 0.0
            if self.is_trained:
                ml_score = float(self.model.score_samples([vec])[0])
                ml_flag = ml_score < self.threshold
                severity = self._severity(ml_score) if ml_flag else 0.0
            attack_prob, clf_flag = None, False
            if self.clf is not None:
                attack_prob = self.clf.proba(vec)
                clf_flag = attack_prob >= config.CLASSIFIER_THRESHOLD
                if clf_flag:
                    severity = max(severity, attack_prob)
            if not hits and not ml_flag and not clf_flag:
                continue
            label = "+".join(hits) if hits else ("known_attack_pattern" if clf_flag else "ml_anomaly")
            detections.append({
                "src": src,
                "label": label,
                "attack_prob": None if attack_prob is None else round(attack_prob, 3),
                "rule_hits": hits,
                "ml_anomaly": bool(ml_flag),
                "ml_score": None if ml_score is None else round(ml_score, 4),
                "severity": round(severity, 3),
                "packets": len(group),
                "ports": sorted({p["dport"] for p in group})[:25],
                "features": {k: round(float(v), 3) for k, v in feats.items()},
            })
        return detections
    def save(self, path=config.MODEL_PATH):
        joblib.dump({"model": self.model, "threshold": self.threshold,
                     "features": FEATURE_NAMES, "sklearn": sklearn.__version__}, path)
        security.sign_file(path)
        print(f"[+] Model saved and signed: {path}")

    @classmethod
    def load(cls, path=config.MODEL_PATH):
        if not security.verify_file(path):
            raise RuntimeError("Model missing or signature invalid - refusing to load it. "
                               "Run the 'train' mode first.")
        blob = joblib.load(path)
        if blob["features"] != FEATURE_NAMES:
            raise RuntimeError("Model was trained with different features - retrain.")
        if blob["sklearn"] != sklearn.__version__:
            print(f"[!] Model built with scikit-learn {blob['sklearn']}, running {sklearn.__version__}")
        ids = cls()
        ids.model, ids.threshold = blob["model"], blob["threshold"]
        ids.model.set_params(isolationforest__n_jobs=1)
        if config.CLASSIFIER_PATH.exists():
            ids.clf = AttackClassifier.load()
            print("[+] Supervised attack classifier loaded.")
        return ids

class PacketCapture:
    realtime = True

    def __init__(self, iface=None, bpf="ip", max_buffer=200_000):
        self.iface, self.bpf = iface, bpf
        self.buffer = deque(maxlen=max_buffer)
        self.lock = threading.Lock()
        self.sniffer = None

    def _handle(self, pkt):
        from scapy.layers.inet import IP, TCP, UDP
        if IP not in pkt:
            return
        ip = pkt[IP]
        dport, flags, proto = 0, "", "OTHER"
        if TCP in pkt:
            dport, flags, proto = pkt[TCP].dport, str(pkt[TCP].flags), "TCP"
        elif UDP in pkt:
            dport, proto = pkt[UDP].dport, "UDP"
        rec = {"ts": time.time(), "src": ip.src, "dst": ip.dst,
               "dport": int(dport), "size": len(pkt), "flags": flags, "proto": proto}
        with self.lock:
            self.buffer.append(rec)

    def start(self):
        from scapy.all import AsyncSniffer
        self.sniffer = AsyncSniffer(prn=self._handle, store=False,
                                    filter=self.bpf, iface=self.iface)
        self.sniffer.start()

    def drain(self):
        with self.lock:
            pkts = list(self.buffer)
            self.buffer.clear()
        return pkts

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass


class SimulatedSource:
    realtime = False

    def __init__(self, attacks=True, attack_every=12, seed=None):
        self.attacks, self.attack_every = attacks, attack_every
        self.rng = random.Random(seed)
        self.tick = 0

    def start(self): pass
    def stop(self): pass

    def _pkt(self, src, dst, dport, size, flags):
        return {"ts": time.time(), "src": src, "dst": dst, "dport": dport,
                "size": max(40, int(size)), "flags": flags, "proto": "TCP"}

    def drain(self):
        self.tick += 1
        r, pkts = self.rng, []
        for host in range(10, 16):
            src = f"192.168.1.{host}"
            ports = r.sample([80, 443, 53, 22, 8080], k=r.randint(1, 3))
            for _ in range(r.randint(10, 30)):
                flags = r.choices(["A", "PA", "S", "SA"], weights=[50, 35, 8, 7])[0]
                pkts.append(self._pkt(src, "192.168.1.1", r.choice(ports), r.gauss(500, 80), flags))
        if self.attacks and self.tick % self.attack_every in (0, 1):
            if (self.tick // self.attack_every) % 2 == 0:      # port scan
                for _ in range(150):
                    pkts.append(self._pkt("203.0.113.50", "192.168.1.1",
                                          r.randint(1, 1024), 60, "S"))
            else:                                              # SYN flood
                for _ in range(800):
                    pkts.append(self._pkt("198.51.100.7", "192.168.1.1", 80, 60, "S"))
        return pkts