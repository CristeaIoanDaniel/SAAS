
import hashlib
import hmac
import os
import secrets
from pathlib import Path
import config
_key = None
def load_key() -> bytes:
    global _key
    if _key:
        return _key
    env = os.environ.get("IDS_HMAC_KEY")
    if env:
        _key = env.encode()
    else:
        if not config.KEY_PATH.exists():
            config.KEY_PATH.write_text(secrets.token_hex(32))
        _key = config.KEY_PATH.read_text().strip().encode()
    return _key
def sign(data: bytes) -> str:
    return hmac.new(load_key(), data, hashlib.sha256).hexdigest()
def verify(data: bytes, signature) -> bool:
    try:
        return hmac.compare_digest(sign(data), signature or "")
    except TypeError:
        return False
def sign_file(path) -> None:
    path = Path(path)
    Path(str(path) + ".sig").write_text(sign(path.read_bytes()))
def verify_file(path) -> bool:
    path = Path(path)
    sig_path = Path(str(path) + ".sig")
    if not path.exists() or not sig_path.exists():
        return False
    return verify(path.read_bytes(), sig_path.read_text().strip())
def json_default(obj):

    if hasattr(obj, "item"):
        return obj.item()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)