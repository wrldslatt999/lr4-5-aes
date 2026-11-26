import pytest
from key_manager import KeyManager


@pytest.fixture(scope="session")
def password():
    return "Correct horse battery staple - AES demo"


@pytest.fixture(scope="session")
def vault(tmp_path_factory, password):
    tmp_path = tmp_path_factory.mktemp("vault")
    km = KeyManager(tmp_path / "private" / "keystore.json")
    rec = km.new_key("default", password)
    a, m = km.keys_for(rec, password)
    return km, rec, a, m
