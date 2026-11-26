"""CLI/REPL для лабораторної: key, enc, dec, bench, logs, shell."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from pathlib import Path

from benchmark import parse_size, run_benchmark
from crypto_aes import ContainerError, decrypt_file, encrypt_file, inspect
from key_manager import InvalidPassword, KeyManagementError, KeyManager
from logger_setup import AuditLogger


def password_from_env_or_prompt(confirm: bool = False) -> str:
    if "AES_LAB_PASSWORD" in os.environ:
        pw = os.environ["AES_LAB_PASSWORD"]
    else:
        pw = getpass.getpass("AES passphrase (not shown): ")
        if confirm and pw != getpass.getpass("Confirm passphrase: "):
            raise ValueError("Passphrase confirmation does not match")
    if not pw:
        raise ValueError("Empty passphrase")
    return pw


def run_crypto(command: str, args, km: KeyManager, log: AuditLogger,
               *, password: str | None = None) -> None:
    start = time.perf_counter()
    mode, size = "", 0
    try:
        src, dst = Path(args.infile), Path(args.outfile)
        pw = password if password is not None else password_from_env_or_prompt()
        aad = args.aad.encode("utf-8")
        if command == "enc":
            rec, key, mac = km.active_keys(args.label, pw)
            mode = args.mode
            if args.block_bits != 128 or args.iv_source != "random":
                raise ValueError("AES block is 128 bits, and IV/nonce must be random")
            res = encrypt_file(src, dst, key, mac, rec["key_id"], mode=mode,
                               padding_mode=args.padding, aad=aad, overwrite=args.force)
            km.record_use(rec["key_id"])
        elif command == "dec":
            header = inspect(src)
            mode = header["mode"]
            rec = km.get_by_id(header["key_id"])
            if args.label and rec["label"] != args.label:
                raise KeyManagementError("Requested label does not match container key")
            key, mac = km.keys_for(rec, pw)
            res = decrypt_file(src, dst, key, mac, aad=aad, overwrite=args.force)
        else:
            raise ValueError("Unknown operation")
        size = res["bytes"]
        dt = (time.perf_counter() - start) * 1000
        log.record(command, "success", mode=mode, size=size, duration_ms=dt)
        print(f"OK | {command} | AES-{res['key_bits']} | {mode.upper()} | {size} bytes | {dt:.2f} ms")
    except Exception as exc:
        dt = (time.perf_counter() - start) * 1000
        log.record(command, "failed", mode=mode, size=size, duration_ms=dt, reason=type(exc).__name__)
        raise


def shell(km, log):
    label = input("Key label: ").strip()
    pw = password_from_env_or_prompt()
    km.active_keys(label, pw)
    print("AES-Lab shell. mode gcm|cbc|ctr; enc SOURCE DEST; dec SOURCE DEST; rotate; exit")
    mode = "gcm"
    while True:
        try:
            tokens = input(f"[AES:{mode}]> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not tokens:
            continue
        if tokens[0] in ("exit", "quit"):
            break
        if tokens[0] == "mode" and len(tokens) == 2 and tokens[1] in ("gcm", "cbc", "ctr"):
            mode = tokens[1]
            print("Selected:", mode.upper())
        elif tokens[0] == "rotate" and len(tokens) == 1:
            new = km.rotate(label, pw)
            log.record("rotate", "success")
            print("Rotated key to:", new["key_id"])
        elif tokens[0] in ("enc", "dec") and len(tokens) == 3:
            opts = argparse.Namespace(infile=tokens[1], outfile=tokens[2], label=label,
                                     mode=mode, padding=None, aad="", force=False,
                                     iv_source="random", block_bits=128)
            try:
                run_crypto(tokens[0], opts, km, log, password=pw)
            except Exception as exc:
                print("ERROR:", type(exc).__name__, str(exc))
        else:
            print("Use: mode gcm|cbc|ctr; enc IN OUT; dec IN OUT; rotate; exit")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LR 4-5: AES authenticated file encryption")
    parser.add_argument("--home", default=".aes-lab", help="Private state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    pkey = sub.add_parser("key", help="Create, rotate, list keys")
    ks = pkey.add_subparsers(dest="action", required=True)
    for name in ("new", "rotate"):
        sp = ks.add_parser(name)
        sp.add_argument("--label", required=True)
        sp.add_argument("--key-bits", type=int, choices=[128, 192, 256], default=None)
    ks.add_parser("list")
    for name in ("enc", "dec"):
        p = sub.add_parser(name)
        p.add_argument("--in", dest="infile", required=True)
        p.add_argument("--out", dest="outfile", required=True)
        p.add_argument("--label", required=name == "enc", default=None)
        p.add_argument("--aad", default="", help="Additional authenticated data; same value on decrypt")
        p.add_argument("--force", action="store_true", help="Overwrite existing output")
        if name == "enc":
            p.add_argument("--mode", choices=["gcm", "cbc", "ctr"], default="gcm")
            p.add_argument("--padding", choices=["none", "pkcs7"], default=None)
            p.add_argument("--block-bits", type=int, choices=[128], default=128)
            p.add_argument("--iv-source", choices=["random"], default="random")
    pb = sub.add_parser("bench", help="Independent ephemeral random-key benchmark")
    pb.add_argument("--sizes", nargs="+", default=["1KB", "64KB", "1MB"])
    pb.add_argument("--modes", nargs="+", choices=["gcm", "cbc", "ctr"], default=["gcm", "cbc", "ctr"])
    pb.add_argument("--repeat", type=int, default=5)
    pb.add_argument("--out-dir", default="benchmarks")
    sub.add_parser("shell")
    lg = sub.add_parser("logs")
    lg.add_argument("action", choices=["summary"])
    args = parser.parse_args(argv)
    home = Path(args.home)
    km = KeyManager(home / "keystore.json")
    log = AuditLogger(home / "logs" / "aes.jsonl")
    try:
        if args.command == "key":
            if args.action == "list":
                print(json.dumps(km.list_keys(), indent=2, ensure_ascii=False))
            else:
                pw = password_from_env_or_prompt(confirm=(args.action == "new"))
                if args.action == "new":
                    rec = km.new_key(args.label, pw, key_bits=args.key_bits or 256)
                else:
                    rec = km.rotate(args.label, pw, key_bits=args.key_bits)
                log.record("key." + args.action, "success")
                print("Key ID:", rec["key_id"], "| AES", rec["key_bits"], "|", rec["status"])
        elif args.command in ("enc", "dec"):
            run_crypto(args.command, args, km, log)
        elif args.command == "shell":
            shell(km, log)
        elif args.command == "logs":
            print(json.dumps(log.summary(), indent=2, ensure_ascii=False))
        elif args.command == "bench":
            report = run_benchmark([parse_size(n) for n in args.sizes], args.modes,
                                   args.repeat, args.out_dir)
            print(f"Recorded {len(report['trials'])} trials: {args.out_dir}/results.md, .csv, .json")
        return 0
    except (OSError, ValueError, KeyManagementError, ContainerError) as exc:
        print(f"ERROR [{type(exc).__name__}]: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
