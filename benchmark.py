"""Repeatable benchmarks with file sizes, elapsed, CPU, and sampled process memory."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import secrets
import statistics
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil
import cryptography

from crypto_aes import decrypt_file, encrypt_file


def parse_size(token: str) -> int:
    upper = token.strip().upper()
    for suffix, mul in (("MIB", 1048576), ("MB", 1048576), ("KIB", 1024), ("KB", 1024)):
        if upper.endswith(suffix):
            return int(float(upper[:-len(suffix)]) * mul)
    return int(upper)


def measure(fn):
    proc = psutil.Process()
    base = proc.memory_info().rss
    peak = [base]
    stop = threading.Event()

    def sample():
        while not stop.wait(0.002):
            peak[0] = max(peak[0], proc.memory_info().rss)

    th = threading.Thread(target=sample, daemon=True)
    th.start()
    begin_cpu = time.process_time()
    start = time.perf_counter_ns()
    try:
        result = fn()
    finally:
        elapsed_ns = time.perf_counter_ns() - start
        cpu_sec = time.process_time() - begin_cpu
        stop.set()
        th.join()
        peak[0] = max(peak[0], proc.memory_info().rss)
    return result, elapsed_ns / 1e9, cpu_sec, max(0, peak[0] - base)


def run_benchmark(sizes: list[int], modes: list[str], repeat: int = 5,
                  output: str | Path = "benchmarks", workdir: str | Path = "outputs") -> dict:
    if not sizes or not modes or repeat < 1 or repeat > 30 or any(x <= 0 or x > 64 * 1048576 for x in sizes):
        raise ValueError("Sizes must be 1..64MiB; repeat must be 1..30")
    outdir, tmpdir = Path(output), Path(workdir)
    outdir.mkdir(parents=True, exist_ok=True)
    tmpdir.mkdir(parents=True, exist_ok=True)
    key, mac_key = secrets.token_bytes(32), secrets.token_bytes(32)
    rows = []
    for n in sizes:
        source = tmpdir / f"benchmark_{n}.bin"
        # Only ephemeral samples, not real private files.
        with source.open("wb") as file:
            remaining = n
            while remaining:
                chunk = secrets.token_bytes(min(256 * 1024, remaining))
                file.write(chunk)
                remaining -= len(chunk)
        with source.open("rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        for mode in modes:
            if mode not in ("gcm", "cbc", "ctr"):
                raise ValueError("Unsupported mode")
            for idx in range(repeat):
                encrypted = tmpdir / f"bench_{n}_{mode}_{idx}.enc"
                restored = tmpdir / f"bench_{n}_{mode}_{idx}.dec"
                _, enc_sec, enc_cpu, enc_rss = measure(
                    lambda: encrypt_file(source, encrypted, key, mac_key, "benchmark-only", mode=mode)
                )
                _, dec_sec, dec_cpu, dec_rss = measure(
                    lambda: decrypt_file(encrypted, restored, key, mac_key)
                )
                with restored.open("rb") as f:
                    verified = hashlib.file_digest(f, "sha256").hexdigest() == digest
                rows.append({
                    "size_bytes": n, "mode": mode, "trial": idx + 1,
                    "encrypt_s": round(enc_sec, 7), "decrypt_s": round(dec_sec, 7),
                    "encrypt_cpu_s": round(enc_cpu, 7), "decrypt_cpu_s": round(dec_cpu, 7),
                    "encrypt_peak_rss_increase_bytes": enc_rss,
                    "decrypt_peak_rss_increase_bytes": dec_rss,
                    "verified_sha256": verified,
                })
                encrypted.unlink()
                restored.unlink()
                if not verified:
                    raise RuntimeError("File hashes differ after decryption")
        source.unlink()
    meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0], "cryptography": cryptography.__version__,
        "psutil": psutil.__version__, "os": platform.platform(),
        "cpu_model": platform.processor() or "not reported",
        "logical_cpu_count": os.cpu_count(),
        "benchmark_keys": "ephemeral random AES-256 and HMAC-256",
        "pbkdf2_included_in_timed_operations": False,
        "memory_metric": "sampled RSS increase compared to pre-operation baseline, sampling interval approximately 2 ms",
        "file_size_base": "binary (1MiB=1048576 bytes)",
        "interpretation": "environment-specific illustration; not a hardware-independent algorithm ranking",
        "sample_count": len(rows),
    }
    with (outdir / "results.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (outdir / "results.json").open("w", encoding="utf-8") as f:
        json.dump({"environment": meta, "trials": rows}, f, ensure_ascii=False, indent=2)
    summary = ["# ЛР №4–5 — вимірювання часу та споживання ресурсів", "",
               f"Дата (UTC): {meta['timestamp_utc']}. Python {meta['python']}; cryptography {meta['cryptography']}; psutil {meta['psutil']}.",
               f"ОС: {meta['os']}; CPU: {meta['cpu_model']}; логічних процесорів: {meta['logical_cpu_count']}.",
               "Шифрування й дешифрування виміряно окремо; PBKDF2 до часу операцій не включено.",
               "Показник пам’яті — *спостережуване* збільшення RSS процесу, а не гарантований піковий обсяг усієї системи.",
               "", "| Розмір | Режим | Повторів | Enc median, мс | Dec median, мс | Enc MiB/s | Dec MiB/s | Peak RSS +, KiB | SHA-256 |",
               "|---:|---|---:|---:|---:|---:|---:|---:|---|"]
    for n in sizes:
        for mode in modes:
            cur = [r for r in rows if r["size_bytes"] == n and r["mode"] == mode]
            e = statistics.median(r["encrypt_s"] for r in cur)
            d = statistics.median(r["decrypt_s"] for r in cur)
            rss = max(max(r["encrypt_peak_rss_increase_bytes"], r["decrypt_peak_rss_increase_bytes"]) for r in cur)
            summary.append(f"| {n/1048576:.4f} MiB | {mode.upper()} | {len(cur)} | {e*1000:.3f} | {d*1000:.3f} | {(n/1048576)/e:.2f} | {(n/1048576)/d:.2f} | {rss/1024:.1f} | {'PASS' if all(r['verified_sha256'] for r in cur) else 'FAIL'} |")
    summary += ["", "Дрібні файли переважно відображають накладні витрати запуску, читання/запису і файлової системи.",
                "GCM автентифікує повідомлення тегом; CBC і CTR в цій реалізації доповнено Encrypt-then-HMAC.",
                "CBC має PKCS#7 за замовчуванням; CTR/GCM не потребують padding. Порівняння отримано в одному середовищі, воно не є універсальним рейтингом AES."]
    (outdir / "results.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    return {"environment": meta, "trials": rows}


if __name__ == "__main__":
    run_benchmark([1024, 65536, 1048576], ["gcm", "cbc", "ctr"], 3)
