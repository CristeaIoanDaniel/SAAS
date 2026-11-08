import ipaddress
import subprocess

import config


class ResponseEngine:
    def __init__(self, dry_run: bool = True, whitelist=()):
        self.dry_run = dry_run
        self.whitelist = set(whitelist)
        self.blocked = set()
        self.quarantined = False
        self.adapters_down = False

    def _run(self, cmd: list) -> bool:
        if self.dry_run:
            print("   [DRY-RUN]", " ".join(cmd))
            return True
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as e:
            print("   [RESPONSE ERROR]", e)
            return False
        if r.returncode != 0:
            print("   [RESPONSE ERROR]", (r.stdout or r.stderr).strip())
        return r.returncode == 0

    def block_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip in self.whitelist or addr.is_loopback or ip in self.blocked:
            return False
        ok = self._run(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=IDS_BLOCK_{ip}", "dir=in", "action=block", f"remoteip={ip}"])
        if ok:
            self.blocked.add(ip)
        return ok

    def unblock_all(self):
        for ip in list(self.blocked):
            if self._run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=IDS_BLOCK_{ip}"]):
                self.blocked.discard(ip)

    def quarantine(self) -> bool:
        if self.quarantined:
            return False
        ok = self._run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,blockoutbound"])
        self.quarantined = ok
        return ok

    def lift_quarantine(self) -> bool:
        ok = self._run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,allowoutbound"])
        if ok:
            self.quarantined = False
        return ok

    def kill_switch(self) -> bool:
        ok = self.quarantine()
        if config.HARD_CUT:
            for n in config.NETWORK_ADAPTERS:
                ok = self._run(["netsh", "interface", "set", "interface",
                                f"name={n}", "admin=disabled"]) and ok
            self.adapters_down = True
        return ok

    def restore_network(self) -> bool:
        ok = True
        for n in config.NETWORK_ADAPTERS:
            ok = self._run(["netsh", "interface", "set", "interface",
                            f"name={n}", "admin=enabled"]) and ok
        self.adapters_down = False
        ok = self._run(["netsh", "advfirewall", "set", "allprofiles",
                        "firewallpolicy", "blockinbound,allowoutbound"]) and ok
        self.quarantined = False
        return ok