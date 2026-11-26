"""Create a *copy* with modified ciphertext, tag or header for authentication tests."""
from __future__ import annotations

import argparse
from pathlib import Path
from crypto_aes import _read_header


def tamper_file(source: str | Path, output: str | Path, *, which: str = "tag") -> Path:
    src, dst = Path(source), Path(output)
    if src.resolve() == dst.resolve():
        raise ValueError("Tampering must not overwrite the original")
    data = bytearray(src.read_bytes())
    with src.open("rb") as f:
        head, _ = _read_header(f)
        start = f.tell()
    taglen = 16 if head["mode"] == "gcm" else 32
    if len(data) < start + taglen:
        raise ValueError("Truncated file")
    if which == "tag":
        data[-1] ^= 0x80
    elif which == "ciphertext":
        if len(data) == start + taglen:
            raise ValueError("No ciphertext to modify")
        data[start + (len(data) - start - taglen) // 2] ^= 0x20
    elif which == "header":
        # Change a hex digit inside IV, preserving JSON structure.
        i = data.find(head["iv"].encode("ascii"))
        if i < 0:
            raise ValueError("IV field is missing")
        data[i] = ord("a") if data[i] != ord("a") else ord("b")
    else:
        raise ValueError("--which: ciphertext, tag, header")
    if dst.exists():
        raise FileExistsError(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("xb") as f:
        f.write(data)
    return dst


def main():
    parser = argparse.ArgumentParser(description="Simulate tampered AES container")
    parser.add_argument("--file", required=True)
    parser.add_argument("--out", help="Default: <file>.tampered")
    parser.add_argument("--which", choices=["ciphertext", "tag", "header"], default="tag")
    args = parser.parse_args()
    out = tamper_file(args.file, args.out or args.file + ".tampered", which=args.which)
    print(f"Created tampered copy: {out} ({args.which})")


if __name__ == "__main__":
    main()
