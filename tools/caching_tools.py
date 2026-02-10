import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)


def _cache_path(key: str) -> Path:
    safe = "".join(c for c in key if c.isalnum() or c in ("_", "-")).strip()
    return CACHE_DIR / f"{safe}.json"


def load_cache(key: str, max_age_seconds: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Load cached dict for `key`. If max_age_seconds is set, returns None if stale.
    """
    path = _cache_path(key)
    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return None

    if not isinstance(payload, dict) or "data" not in payload or "ts" not in payload:
        return None

    if max_age_seconds is not None:
        age = int(time.time()) - int(payload.get("ts", 0))
        if age > max_age_seconds:
            return None

    data = payload.get("data")
    return data if isinstance(data, dict) else None


def save_cache(key: str, data: Dict[str, Any]) -> None:
    """
    Save dict `data` for `key`.
    """
    path = _cache_path(key)
    payload = {"ts": int(time.time()), "data": data}
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def get_or_refresh(
    key: str,
    fn: Callable[[], Dict[str, Any]],
    max_age_seconds: Optional[int] = None,
    force: bool = False
) -> Dict[str, Any]:
    """
    Return cached value unless forced or stale/missing, then recompute and cache.
    """
    if not force:
        cached = load_cache(key, max_age_seconds=max_age_seconds)
        if cached is not None:
            return cached

    try:
        data = fn()
        if not isinstance(data, dict):
            data = {"error": f"{key} did not return a dict"}
    except Exception as e:
        data = {"error": str(e)}

    save_cache(key, data)
    return data
