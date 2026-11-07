import hashlib
import json
import os
from pathlib import Path
import config
import security
class FileIntegrityMonitor:
    def __init__(self, roots=None, baseline_path=None, extensions=None, exclude=None):
        self.roots = [Path(r) for r in (roots or config.WATCHED_PATHS)]
        self.baseline_path = Path(baseline_path or config.FIM_BASELINE_PATH)
        self.extensions = config.WATCH_EXTENSIONS if extensions is None else extensions
        self.exclude = config.FIM_EXCLUDE_DIRS if exclude is None else exclude

    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    def snapshot(self) -> dict:
        result = {}
        for root in self.roots:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in self.exclude]
                for name in filenames:
                    p = Path(dirpath) / name
                    if self.extensions and p.suffix.lower() not in self.extensions:
                        continue
                    digest = self._sha256(p)
                    if digest:
                        result[str(p)] = digest
        return result

    def build_baseline(self) -> int:
        snap = self.snapshot()
        self.baseline_path.write_text(json.dumps(snap, indent=1, sort_keys=True))
        security.sign_file(self.baseline_path)
        return len(snap)

    def ensure_baseline(self):
        if not self.baseline_path.exists():
            n = self.build_baseline()
            print(f"[+] FIM baseline created for {n} files.")

    def check(self) -> list:
        """Returns a list of {'path','change'}; empty list = everything intact."""
        if not self.baseline_path.exists():
            self.build_baseline()
            return []
        if not security.verify_file(self.baseline_path):
            return [{"path": str(self.baseline_path), "change": "baseline_tampered"}]
        base = json.loads(self.baseline_path.read_text())
        now = self.snapshot()
        changes = []
        for path, digest in now.items():
            if path not in base:
                changes.append({"path": path, "change": "created"})
            elif base[path] != digest:
                changes.append({"path": path, "change": "modified"})
        for path in base:
            if path not in now:
                changes.append({"path": path, "change": "deleted"})
        return changes


def check_file_integrity() -> bool:
    return bool(FileIntegrityMonitor().check())