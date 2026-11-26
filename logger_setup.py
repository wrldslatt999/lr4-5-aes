"""JSONL audit log: metadata only, never passwords, keys or file contents."""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, path: str | Path = ".aes-lab/logs/aes.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, operation: str, status: str, *, mode: str = "", size: int = 0,
               duration_ms: float = 0.0, reason: str = "") -> None:
        event = {"time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "event": operation, "status": status, "mode": mode,
                 "size_bytes": size, "duration_ms": round(duration_ms, 3)}
        if reason:
            event["error_type"] = reason[:80]
        fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "a", encoding="utf-8") as out:
                out.write(json.dumps(event, ensure_ascii=False) + "\n")
        finally:
            if os.path.exists(self.path) and os.name == "posix":
                os.chmod(self.path, 0o600)

    def summary(self) -> dict[str, int]:
        counts = Counter()
        if not self.path.exists():
            return {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                counts[f"{item['event']}:{item['status']}"] += 1
            except (ValueError, KeyError, TypeError):
                counts["invalid_line"] += 1
        return dict(sorted(counts.items()))
