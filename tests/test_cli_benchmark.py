import json
import os
from pathlib import Path

from aes_cli import main
from benchmark import parse_size, run_benchmark
from logger_setup import AuditLogger


def test_cli_roundtrip_and_logging(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AES_LAB_PASSWORD", "correct-demo-password-12345")
    home = tmp_path / "private"
    src = tmp_path / "input.txt"; src.write_text("Українські дані", encoding="utf-8")
    assert main(["--home", str(home), "key", "new", "--label", "default"]) == 0
    for mode in ("gcm", "cbc", "ctr"):
        enc = tmp_path / (mode + ".enc")
        dec = tmp_path / (mode + ".dec")
        assert main(["--home", str(home), "enc", "--in", str(src), "--out", str(enc), "--label", "default", "--mode", mode]) == 0
        assert main(["--home", str(home), "dec", "--in", str(enc), "--out", str(dec), "--label", "default"]) == 0
        assert dec.read_bytes() == src.read_bytes()
    assert main(["--home", str(home), "key", "rotate", "--label", "default"]) == 0
    assert main(["--home", str(home), "logs", "summary"]) == 0
    lines = (home / "logs" / "aes.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 8
    assert all("correct-demo-password" not in line for line in lines)
    assert AuditLogger(home / "logs" / "aes.jsonl").summary()["enc:success"] == 3


def test_cli_failure_logged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AES_LAB_PASSWORD", "wrong-but-long-enough-password")
    home = tmp_path / ".aes-lab"
    src = tmp_path / "p"; src.write_bytes(b"test")
    assert main(["--home", str(home), "enc", "--in", str(src), "--out", str(tmp_path / "enc"), "--label", "none"]) == 2
    events = [json.loads(s) for s in (home / "logs" / "aes.jsonl").read_text().splitlines()]
    assert events[-1]["status"] == "failed"
    assert events[-1]["error_type"] == "KeyManagementError"


def test_benchmark_output_and_hashes(tmp_path):
    result = run_benchmark([1024], ["gcm", "cbc", "ctr"], 1,
                           output=tmp_path / "results", workdir=tmp_path / "scratch")
    assert len(result["trials"]) == 3
    assert all(r["verified_sha256"] for r in result["trials"])
    assert (tmp_path / "results" / "results.csv").exists()
    assert (tmp_path / "results" / "results.md").exists()
    assert (tmp_path / "results" / "results.json").exists()
    assert parse_size("1MB") == 1048576
    assert parse_size("64KB") == 65536
