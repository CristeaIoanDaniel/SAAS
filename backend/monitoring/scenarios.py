import random
import time

SCENARIOS = ["normal", "port_scan", "syn_flood", "host_sweep", "custom"]


def _pkt(src, dst, dport, size, flags):
    return {"ts": time.time(), "src": src, "dst": dst, "dport": int(dport),
            "size": max(40, int(size)), "flags": flags, "proto": "TCP"}
def background(rng: random.Random, hosts: int = 6) -> list:
    pkts = []
    for h in range(10, 10 + hosts):
        src = f"192.168.1.{h}"
        ports = rng.sample([80, 443, 53, 22, 8080], k=rng.randint(1, 3))
        for _ in range(rng.randint(10, 30)):
            flags = rng.choices(["A", "PA", "S", "SA"], weights=[50, 35, 8, 7])[0]
            pkts.append(_pkt(src, "192.168.1.1", rng.choice(ports), rng.gauss(500, 80), flags))
    return pkts


def build(s: dict, rng: random.Random) -> list:
    """s = {type, src_ip, packets, unique_ports, syn_ratio, avg_size, target_ip}"""
    kind, src, n = s["type"], s["src_ip"], int(s["packets"])
    dst = s.get("target_ip", "192.168.1.1")
    pkts = []
    if kind == "port_scan":                      # many different ports, bare SYNs
        pkts = [_pkt(src, dst, rng.randint(1, 1024), 60, "S") for _ in range(n)]
    elif kind == "syn_flood":                    # many SYNs on one port
        pkts = [_pkt(src, dst, 80, 60, "S") for _ in range(n)]
    elif kind == "host_sweep":                   # same probe to many machines
        pkts = [_pkt(src, f"192.168.1.{1 + i % 254}", 80, 60, "S") for i in range(n)]
    elif kind == "custom":                       # you choose the traffic shape
        ports = max(1, int(s["unique_ports"]))
        size = float(s["avg_size"])
        for i in range(n):
            flags = "S" if rng.random() < float(s["syn_ratio"]) else "PA"
            pkts.append(_pkt(src, dst, (i % ports) + 1, rng.gauss(size, size * 0.1), flags))
    return pkts                                  # "normal" adds nothing beyond background