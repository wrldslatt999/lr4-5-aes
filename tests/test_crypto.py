import json
from pathlib import Path

import pytest

from crypto_aes import ContainerError, IntegrityError, decrypt_file, encrypt_file, inspect
from key_manager import InvalidPassword, KeyManagementError, KeyManager
from tamper_demo import tamper_file


@pytest.mark.parametrize("mode", ["gcm", "cbc", "ctr"])
@pytest.mark.parametrize("data", [b"", b"x", b"a" * 16, b"a" * 37, b"1234" * 65536])
def test_roundtrip(tmp_path, vault, mode, data):
    _, rec, key, mac = vault
    src, enc, out = [tmp_path / x for x in ("source.bin", "cipher.enc", "restored.bin")]
    src.write_bytes(data)
    details = encrypt_file(src, enc, key, mac, rec["key_id"], mode=mode)
    assert inspect(enc)["mode"] == mode
    assert details["bytes"] == len(data)
    restored = decrypt_file(enc, out, key, mac)
    assert restored["bytes"] == len(data)
    assert out.read_bytes() == data


@pytest.mark.parametrize("mode", ["gcm", "cbc", "ctr"])
@pytest.mark.parametrize("which", ["tag", "ciphertext", "header"])
def test_tampering_rejected_and_no_output(tmp_path, vault, mode, which):
    _, rec, key, mac = vault
    src, enc, damaged, out = [tmp_path / x for x in ("a.txt", "b.enc", "b.broken", "output")]
    src.write_bytes(b"test data " * 900)
    encrypt_file(src, enc, key, mac, rec["key_id"], mode=mode)
    tamper_file(enc, damaged, which=which)
    with pytest.raises((IntegrityError, ContainerError)):
        decrypt_file(damaged, out, key, mac)
    assert not out.exists()
    assert not list(tmp_path.glob(".aeslab-*"))


@pytest.mark.parametrize("mode", ["gcm", "cbc", "ctr"])
def test_aad_accepted_and_authenticated(tmp_path, vault, mode):
    _, rec, key, mac = vault
    src, enc, out = [tmp_path / x for x in ("a", "b", "c")]
    src.write_bytes(b"ABC " * 11)
    encrypt_file(src, enc, key, mac, rec["key_id"], mode=mode, aad=b"context-1")
    with pytest.raises(IntegrityError):
        decrypt_file(enc, out, key, mac, aad=b"context-2")
    assert not out.exists()
    decrypt_file(enc, out, key, mac, aad=b"context-1")
    assert out.read_bytes() == src.read_bytes()


def test_cbc_without_padding_rejects_unaligned_source(tmp_path, vault):
    _, rec, key, mac = vault
    src = tmp_path / "a"; src.write_bytes(b"unaligned")
    with pytest.raises(ContainerError, match="multiple of 16"):
        encrypt_file(src, tmp_path / "b", key, mac, rec["key_id"], mode="cbc", padding_mode="none")


def test_cbc_without_padding_accepts_aligned_source(tmp_path, vault):
    _, rec, key, mac = vault
    src = tmp_path / "a"; src.write_bytes(b"A" * 32)
    enc, out = tmp_path / "b", tmp_path / "c"
    encrypt_file(src, enc, key, mac, rec["key_id"], mode="cbc", padding_mode="none")
    decrypt_file(enc, out, key, mac)
    assert out.read_bytes() == b"A" * 32


def test_gcm_cbc_nonce_randomized(tmp_path, vault):
    _, rec, key, mac = vault
    source = tmp_path / "file"; source.write_bytes(b"fixed input" * 10)
    for mode in ("gcm", "cbc", "ctr"):
        a, b = tmp_path / (mode + "1"), tmp_path / (mode + "2")
        encrypt_file(source, a, key, mac, rec["key_id"], mode=mode)
        encrypt_file(source, b, key, mac, rec["key_id"], mode=mode)
        assert a.read_bytes() != b.read_bytes()
        assert inspect(a)["iv"] != inspect(b)["iv"]


def test_wrong_key_and_truncation(tmp_path, vault):
    _, rec, key, mac = vault
    source = tmp_path / "x"; source.write_bytes(b"example")
    enc, out = tmp_path / "y", tmp_path / "z"
    encrypt_file(source, enc, key, mac, rec["key_id"])
    with pytest.raises(IntegrityError):
        decrypt_file(enc, out, bytes(len(key)), mac)
    assert not out.exists()
    enc.write_bytes(enc.read_bytes()[:10])
    with pytest.raises(ContainerError):
        decrypt_file(enc, out, key, mac)
    assert not out.exists()


def test_bad_key_lengths(tmp_path, vault):
    _, rec, _, mac = vault
    src = tmp_path / "a"; src.write_bytes(b"stuff")
    with pytest.raises(ContainerError):
        encrypt_file(src, tmp_path / "b", b"bad", mac, rec["key_id"])


def test_no_clobber_and_no_same_path(tmp_path, vault):
    _, rec, key, mac = vault
    src, enc, out = [tmp_path / n for n in ("a", "b", "c")]
    src.write_bytes(b"plain")
    with pytest.raises(ContainerError):
        encrypt_file(src, src, key, mac, rec["key_id"])
    enc.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        encrypt_file(src, enc, key, mac, rec["key_id"])
    encrypt_file(src, enc, key, mac, rec["key_id"], overwrite=True)
    out.write_bytes(b"do not overwrite")
    with pytest.raises(FileExistsError):
        decrypt_file(enc, out, key, mac)
    assert out.read_bytes() == b"do not overwrite"


def test_wrong_password_and_rotation_decrypt_old(tmp_path, password):
    km = KeyManager(tmp_path / "store" / "keys.json")
    old = km.new_key("lab", password, key_bits=128)
    old_enc, old_mac = km.keys_for(old, password)
    with pytest.raises(InvalidPassword):
        km.keys_for(old, "not-correct")
    src, enc, result = [tmp_path / x for x in ("file", "encrypted", "decrypted")]
    src.write_bytes(b"old data")
    encrypt_file(src, enc, old_enc, old_mac, old["key_id"])
    new = km.rotate("lab", password, key_bits=256)
    assert new["key_id"] != old["key_id"]
    assert new["salt"] != old["salt"]
    assert km.get_by_id(old["key_id"])["status"] == "retired"
    enc_key, mac_key = km.keys_for(km.get_by_id(inspect(enc)["key_id"]), password)
    decrypt_file(enc, result, enc_key, mac_key)
    assert result.read_bytes() == src.read_bytes()
    assert len(km.active_keys("lab", password)[1]) == 32


def test_key_store_metadata_and_permissions(tmp_path, password):
    path = tmp_path / "state" / "keystore.json"
    km = KeyManager(path)
    rec = km.new_key("lab", password, key_bits=192)
    contents = path.read_text()
    assert password not in contents
    assert "key_id" in contents and "salt" in contents
    assert "proof" in contents
    assert not any(k in contents for k in ['"enc_key"', '"mac_key"'])
    assert len(km.active_keys("lab", password)[1]) == 24
    if __import__("os").name == "posix":
        assert (path.stat().st_mode & 0o077) == 0
    with pytest.raises(KeyManagementError):
        km.new_key("lab", password)


def test_key_limits_and_expiry(tmp_path, password, monkeypatch):
    import key_manager
    km = KeyManager(tmp_path / "keys.json")
    rec = km.new_key("test", password)
    monkeypatch.setattr(key_manager, "MAX_ENCRYPTIONS", 1)
    km.active_keys("test", password)
    km.record_use(rec["key_id"])
    with pytest.raises(KeyManagementError, match="Rotate"):
        km.active_keys("test", password)
    new = km.rotate("test", password)
    monkeypatch.setattr(key_manager, "MAX_KEY_AGE_DAYS", 0)
    new["created_at"] = 1
    with pytest.raises(KeyManagementError, match="age"):
        km.active_keys("test", password)


def test_invalid_header_and_padding_rejected(tmp_path, vault):
    _, rec, key, mac = vault
    src = tmp_path / "a"; src.write_bytes(b"abc")
    enc, out = tmp_path / "b", tmp_path / "c"
    encrypt_file(src, enc, key, mac, rec["key_id"], mode="cbc")
    data = enc.read_bytes()
    enc.write_bytes(b"NOPE" + data[4:])
    with pytest.raises(ContainerError):
        decrypt_file(enc, out, key, mac)
    assert not out.exists()
