"""
secure_transport.py - sends alerts to a remote collector safely.

 * HTTPS only, certificate verified, TLS 1.2+
 * Each message is signed with HMAC(timestamp + body) -> tamper + replay protection
 * Sending happens in a background thread; failed alerts are spooled to disk
"""
import json
import queue
import ssl
import threading
import time
import urllib.request

import config
import security


class SecureAlertSender:
    def __init__(self, url: str = config.COLLECTOR_URL, ca_file: str = config.COLLECTOR_CA):
        self.url = url
        self.enabled = bool(url)
        self.q = queue.Queue(maxsize=1000)
        if not self.enabled:
            return
        if not url.lower().startswith("https://"):
            raise ValueError("Collector URL must start with https:// (plain HTTP is refused).")
        self.ctx = ssl.create_default_context(cafile=ca_file or None)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        threading.Thread(target=self._worker, daemon=True).start()

    def send(self, event: dict):
        if not self.enabled:
            return
        try:
            self.q.put_nowait(event)
        except queue.Full:
            self._spool(event)

    def _post(self, event: dict) -> bool:
        body = json.dumps(event, sort_keys=True, default=security.json_default).encode()
        ts = str(int(time.time()))
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json",
            "X-IDS-Timestamp": ts,
            "X-IDS-Signature": security.sign(ts.encode() + b"." + body)})
        with urllib.request.urlopen(req, timeout=5, context=self.ctx) as r:
            return r.status == 200

    def _worker(self):
        while True:
            event = self.q.get()
            for attempt in range(3):
                try:
                    if self._post(event):
                        break
                except Exception:
                    pass
                time.sleep(2 ** attempt)
            else:
                self._spool(event)
            self.q.task_done()

    def _spool(self, event: dict):
        with open(config.SPOOL_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=security.json_default) + "\n")

    def flush(self, timeout: float = 5.0):
        end = time.time() + timeout
        while self.enabled and self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.1)