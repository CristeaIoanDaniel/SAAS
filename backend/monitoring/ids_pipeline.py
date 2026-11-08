import argparse
import socket
import time

import config
import settings
from file_integrity import FileIntegrityMonitor
from incident_log import AttackerTracker, IncidentLog
from packet_monitor import (AttackClassifier, NetworkIDS, PacketCapture,
                            SimulatedSource, iter_sources)
from pipeline import Pipeline
from response import ResponseEngine
from secure_transport import SecureAlertSender


def local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def make_source(args, attacks: bool):
    return SimulatedSource(attacks=attacks) if args.simulate else PacketCapture(iface=args.iface)


# --------------------------------------------------------------------------
# Training
# --------------------------------------------------------------------------
def train(args):
    whitelist = set(config.WHITELIST) | {local_ip()}
    source = make_source(args, attacks=False)
    windows = args.minutes * 60 // config.WINDOW_SECONDS
    print(f"[*] Collecting {windows} windows of NORMAL traffic "
          f"({'simulated' if args.simulate else 'live - use the network normally, no attacks!'})")
    rows = []
    source.start()
    try:
        for i in range(windows):
            if source.realtime:
                time.sleep(config.WINDOW_SECONDS)
            pkts = source.drain()
            rows += [vec for _, _, vec in iter_sources(pkts, config.WINDOW_SECONDS, whitelist)]
            if (i + 1) % 12 == 0:
                print(f"    {i + 1}/{windows} windows, {len(rows)} samples")
    finally:
        source.stop()
    ids = NetworkIDS()
    ids.train(rows)
    ids.save()


def train_labeled(args):
    whitelist = set(config.WHITELIST) | {local_ip()}
    attackers = set(args.attacker_ip or [])
    if args.simulate:
        attackers |= {"203.0.113.50", "198.51.100.7"}
    if not attackers:
        print("[!] Give the attacker machine's IP(s): --attacker-ip 192.168.1.50")
        return
    source = make_source(args, attacks=True)
    windows = args.minutes * 60 // config.WINDOW_SECONDS
    print(f"[*] Collecting {windows} windows. Known attackers: {sorted(attackers)}")
    if not args.simulate:
        print("[*] Run your attacks NOW from those machines (lab only), mixed with normal use.")
    X, y = [], []
    source.start()
    try:
        for i in range(windows):
            if source.realtime:
                time.sleep(config.WINDOW_SECONDS)
            for src, _, vec in iter_sources(source.drain(), config.WINDOW_SECONDS, whitelist):
                X.append(vec)
                y.append(1 if src in attackers else 0)
            if (i + 1) % 12 == 0:
                print(f"    {i + 1}/{windows} windows | normal={y.count(0)} attack={y.count(1)}")
    finally:
        source.stop()
    clf = AttackClassifier()
    clf.train(X, y)
    clf.save()


# --------------------------------------------------------------------------
# Monitoring
# --------------------------------------------------------------------------
def wait_for_window(source, pipe):
    """Sleep one window, but check for dashboard commands twice a second."""
    end = time.time() + (config.WINDOW_SECONDS if source.realtime else 1)
    while time.time() < end:
        cmd = settings.take_command()
        if cmd == "cut":
            pipe.manual_cut()
        elif cmd == "restore":
            pipe.manual_restore()
        time.sleep(0.5)


def run(args):
    whitelist = set(config.WHITELIST) | {local_ip()}
    ids = NetworkIDS.load()
    fim = FileIntegrityMonitor()
    fim.ensure_baseline()
    log, tracker = IncidentLog(), AttackerTracker()
    sender = SecureAlertSender()
    resp = ResponseEngine(dry_run=not args.live_actions, whitelist=whitelist)
    pipe = Pipeline(ids, resp, log, tracker, sender)       # risk, blocking and kill switch live here
    source = make_source(args, attacks=True)

    ok, msg = IncidentLog.verify()
    print(f"[*] Incident log check: {msg}")
    if not ok:
        print("[!] WARNING: previous log was tampered with!")

    log.append({"type": "ids_started", "simulate": args.simulate, "dry_run": resp.dry_run})
    print(f"[*] Monitoring started | actions: {'DRY-RUN' if resp.dry_run else 'LIVE'} | Ctrl+C to stop")
    source.start()
    last_fim, last_fim_sig = 0.0, None

    try:
        while True:
            wait_for_window(source, pipe)

            fim_changes, now = None, time.time()
            if now - last_fim >= config.FIM_INTERVAL:
                fim_changes, last_fim = fim.check(), now

            report, detections = pipe.process(source.drain(), config.WINDOW_SECONDS,
                                              fim_changes, whitelist)

            if fim_changes is not None:
                sig = tuple(sorted((c["path"], c["change"]) for c in fim_changes))
                if fim_changes and sig != last_fim_sig:
                    rec = log.append({"type": "fim_breach", "changes": fim_changes,
                                      "host_score": report["host_score"]})
                    sender.send(rec)
                    print(f"[!] FILE INTEGRITY BREACH: {fim_changes}")
                last_fim_sig = sig

            for d in detections:
                info = report["per_ip"].get(d["src"], {"score": 0, "action": "PASS"})
                print(f"[!] {d['src']:<15} {d['label']:<18} sev={d['severity']:<5} "
                      f"pkts={d['packets']:<4} risk={info['score']:<5} -> {info['action']}")

            cut = " | NETWORK CUT" if (resp.quarantined or resp.adapters_down) else ""
            print(f"[{time.strftime('%H:%M:%S')}] flagged={len(detections)} "
                  f"overall={report['overall']:.0f} host={report['host_score']:.0f} "
                  f"action={report['action']}{cut}")
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        source.stop()
        resp.unblock_all()                           # leave the firewall as we found it
        if resp.quarantined or resp.adapters_down:
            resp.restore_network()                   # re-enable adapters + firewall policy
        log.append({"type": "ids_stopped"})


def restore(args):
    """Emergency recovery: re-enable adapters and reset the firewall policy."""
    ok = ResponseEngine(dry_run=False).restore_network()
    print("[+] Network restored." if ok else "[!] Restore reported errors - run from an ADMIN shell "
                                             "and check config.NETWORK_ADAPTERS names.")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ML-assisted IDS")
    ap.add_argument("mode", choices=["train", "run", "report", "verify", "rebaseline", "restore"])
    ap.add_argument("--simulate", action="store_true", help="use synthetic traffic (no admin needed)")
    ap.add_argument("--minutes", type=int, default=30, help="baseline length for 'train'")
    ap.add_argument("--iface", default=None, help="network interface name for live capture")
    ap.add_argument("--labeled", action="store_true",
                    help="with train: supervised training on labeled attack traffic")
    ap.add_argument("--attacker-ip", nargs="+", help="IP(s) of YOUR lab attacker machine(s)")
    ap.add_argument("--live-actions", action="store_true",
                    help="actually change firewall rules / disable adapters (default is dry-run)")
    args = ap.parse_args()

    if args.mode == "run" and args.simulate and args.live_actions:
        ap.error("--simulate with --live-actions would cut your real network; use one or the other")

    if args.mode == "train":
        train_labeled(args) if args.labeled else train(args)
    elif args.mode == "run":
        run(args)
    elif args.mode == "report":
        print(AttackerTracker().report())
    elif args.mode == "verify":
        ok, msg = IncidentLog.verify()
        print(("[OK] " if ok else "[TAMPERED] ") + msg)
    elif args.mode == "rebaseline":
        print(f"[+] FIM baseline rebuilt for {FileIntegrityMonitor().build_baseline()} files.")
    elif args.mode == "restore":
        restore(args)


if __name__ == "__main__":
    main()