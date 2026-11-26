"""Chunked authenticated AES file containers: GCM, CBC+HMAC, CTR+HMAC."""
from __future__ import annotations

import json
import os
import secrets
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import (BLOCK_BITS, CHUNK_SIZE, IV_BYTES, MAGIC, MAX_HEADER_BYTES,
                    NONCE_BYTES_GCM, TAG_GCM_BYTES, TAG_HMAC_BYTES, VERSION)


class ContainerError(ValueError):
    pass


class IntegrityError(ContainerError):
    pass


def _ensure_paths(src: str | Path, dst: str | Path, overwrite: bool) -> tuple[Path, Path]:
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise FileNotFoundError(src)
    if src.resolve() == dst.resolve():
        raise ContainerError("Source and destination must differ")
    if dst.exists() and not overwrite:
        raise FileExistsError(f"Output exists: {dst}; supply --force to replace it")
    dst.parent.mkdir(parents=True, exist_ok=True)
    return src, dst


def _temporary(dst: Path):
    fd, name = tempfile.mkstemp(prefix=".aeslab-", dir=dst.parent)
    os.chmod(name, 0o600)
    return os.fdopen(fd, "wb"), name


def _prefix(header: dict) -> bytes:
    raw = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > MAX_HEADER_BYTES:
        raise ContainerError("Header too long")
    return MAGIC + struct.pack(">H", len(raw)) + raw


def _read_header(fileobj) -> tuple[dict, bytes]:
    pre = fileobj.read(6)
    if len(pre) != 6 or pre[:4] != MAGIC:
        raise ContainerError("Invalid container magic or truncated header")
    count = struct.unpack(">H", pre[4:])[0]
    if not 0 < count <= MAX_HEADER_BYTES:
        raise ContainerError("Invalid header size")
    h = fileobj.read(count)
    if len(h) != count:
        raise ContainerError("Truncated header")
    try:
        head = json.loads(h)
        mode = head["mode"]
        nonce = bytes.fromhex(head["iv"])
        if (head["v"] != VERSION or mode not in ("gcm", "cbc", "ctr")
                or head["block_bits"] != 128 or head["key_bits"] not in (128, 192, 256)
                or head["padding"] not in ("pkcs7", "none")
                or len(nonce) != (NONCE_BYTES_GCM if mode == "gcm" else IV_BYTES)
                or (mode != "cbc" and head["padding"] != "none")
                or not isinstance(head["key_id"], str)):
            raise ValueError("Invalid header fields")
    except (ValueError, TypeError, KeyError) as exc:
        raise ContainerError("Malformed or unsupported header") from exc
    return head, pre + h


def inspect(path: str | Path) -> dict:
    with open(path, "rb") as f:
        h, _ = _read_header(f)
    return h


def _aad_bytes(prefix: bytes, aad: bytes) -> bytes:
    # Framing prevents ambiguity between authenticated header and external data.
    return prefix + struct.pack(">Q", len(aad)) + aad


def encrypt_file(src: str | Path, dst: str | Path, key: bytes, mac_key: bytes,
                 key_id: str, *, mode: str = "gcm", padding_mode: str | None = None,
                 aad: bytes = b"", overwrite: bool = False) -> dict:
    if mode not in ("gcm", "cbc", "ctr"):
        raise ContainerError("Supported modes: gcm, cbc, ctr")
    if len(key) not in (16, 24, 32) or len(mac_key) != 32:
        raise ContainerError("Invalid encryption or MAC key length")
    pad = padding_mode or ("pkcs7" if mode == "cbc" else "none")
    if (mode == "cbc" and pad not in ("pkcs7", "none")) or (mode != "cbc" and pad != "none"):
        raise ContainerError("CBC supports pkcs7/none; GCM/CTR use none")
    src, dst = _ensure_paths(src, dst, overwrite)
    if mode == "cbc" and pad == "none" and src.stat().st_size % 16:
        raise ContainerError("CBC without PKCS7 requires a multiple of 16 bytes")
    iv = secrets.token_bytes(12 if mode == "gcm" else 16)
    header = {"v": VERSION, "key_id": key_id, "mode": mode, "iv": iv.hex(),
              "key_bits": len(key) * 8, "block_bits": 128, "padding": pad}
    pre = _prefix(header)
    if mode == "gcm":
        enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(_aad_bytes(pre, aad))
        mac = None
    else:
        enc = Cipher(algorithms.AES(key), modes.CBC(iv) if mode == "cbc" else modes.CTR(iv)).encryptor()
        mac = crypto_hmac.HMAC(mac_key, hashes.SHA256())
        mac.update(_aad_bytes(pre, aad))
    padder = padding.PKCS7(128).padder() if mode == "cbc" and pad == "pkcs7" else None
    tmp = None
    try:
        f, tmp = _temporary(dst)
        with f as out, open(src, "rb") as inp:
            out.write(pre)
            while chunk := inp.read(CHUNK_SIZE):
                plain = padder.update(chunk) if padder else chunk
                ct = enc.update(plain)
                out.write(ct)
                if mac:
                    mac.update(ct)
            if padder:
                tail = enc.update(padder.finalize()) + enc.finalize()
            else:
                tail = enc.finalize()
            out.write(tail)
            if mac:
                mac.update(tail)
            tag = enc.tag if mode == "gcm" else mac.finalize()
            out.write(tag)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dst)
        tmp = None
        return {"mode": mode, "key_bits": len(key) * 8, "tag_bytes": len(tag),
                "bytes": src.stat().st_size, "key_id": key_id}
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def decrypt_file(src: str | Path, dst: str | Path, key: bytes, mac_key: bytes,
                 *, aad: bytes = b"", overwrite: bool = False) -> dict:
    src, dst = _ensure_paths(src, dst, overwrite)
    with open(src, "rb") as f:
        head, pre = _read_header(f)
        data_start = f.tell()
        length = src.stat().st_size - data_start
        mode = head["mode"]
        taglen = TAG_GCM_BYTES if mode == "gcm" else TAG_HMAC_BYTES
        ct_len = length - taglen
        if ct_len < 0 or (mode == "cbc" and (ct_len == 0 or ct_len % 16)):
            raise ContainerError("Truncated or unaligned ciphertext")
        if len(key) * 8 != head["key_bits"] or len(mac_key) != 32:
            raise ContainerError("Wrong key sizes for encrypted file")
        f.seek(data_start + ct_len)
        tag = f.read(taglen)
        if len(tag) != taglen:
            raise ContainerError("Truncated authentication tag")
        iv = bytes.fromhex(head["iv"])
        if mode in ("cbc", "ctr"):
            # Authenticate *entire ciphertext* BEFORE decrypting any byte.
            mac = crypto_hmac.HMAC(mac_key, hashes.SHA256())
            mac.update(_aad_bytes(pre, aad))
            f.seek(data_start)
            remaining = ct_len
            while remaining:
                chunk = f.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise ContainerError("Truncated ciphertext")
                mac.update(chunk)
                remaining -= len(chunk)
            try:
                mac.verify(tag)
            except InvalidSignature as exc:
                raise IntegrityError("Authentication failed: ciphertext, header or AAD changed") from exc
        dec = Cipher(algorithms.AES(key),
                     modes.GCM(iv, tag) if mode == "gcm" else modes.CBC(iv) if mode == "cbc" else modes.CTR(iv)).decryptor()
        if mode == "gcm":
            dec.authenticate_additional_data(_aad_bytes(pre, aad))
        unpadder = padding.PKCS7(128).unpadder() if mode == "cbc" and head["padding"] == "pkcs7" else None
        tmp = None
        try:
            out, tmp = _temporary(dst)
            with out:
                f.seek(data_start)
                remaining = ct_len
                while remaining:
                    chunk = f.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ContainerError("Truncated ciphertext")
                    pt = dec.update(chunk)
                    out.write(unpadder.update(pt) if unpadder else pt)
                    remaining -= len(chunk)
                try:
                    tail = dec.finalize()
                    if unpadder:
                        tail = unpadder.update(tail) + unpadder.finalize()
                except InvalidTag as exc:
                    raise IntegrityError("Authentication failed: invalid GCM tag or AAD") from exc
                except ValueError as exc:
                    raise IntegrityError("Invalid CBC padding") from exc
                out.write(tail)
                out.flush()
                os.fsync(out.fileno())
            os.replace(tmp, dst)
            tmp = None
            return {"mode": mode, "key_bits": head["key_bits"], "bytes": dst.stat().st_size,
                    "key_id": head["key_id"]}
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
