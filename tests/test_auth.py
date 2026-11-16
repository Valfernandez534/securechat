import json
import os
import stat

from securechat.auth import UserStore


def test_register_and_verify(tmp_path):
    store = UserStore(str(tmp_path / "users.json"))
    assert store.register("alice", "correct horse")
    assert store.verify("alice", "correct horse")
    assert not store.verify("alice", "wrong password")
    assert not store.verify("nobody", "correct horse")


def test_duplicate_register(tmp_path):
    store = UserStore(str(tmp_path / "users.json"))
    assert store.register("alice", "password1")
    assert not store.register("alice", "password2")
    assert store.verify("alice", "password1")


def test_password_not_stored_in_clear(tmp_path):
    path = tmp_path / "users.json"
    UserStore(str(path)).register("alice", "my secret pass")
    content = path.read_text()
    assert "my secret pass" not in content
    assert set(json.loads(content)["alice"]) == {"salt", "hash"}


def test_same_password_gives_different_hashes(tmp_path):
    store = UserStore(str(tmp_path / "users.json"))
    store.register("alice", "same password")
    store.register("bob", "same password")
    assert store.users["alice"]["hash"] != store.users["bob"]["hash"]


def test_store_is_reloaded_and_private(tmp_path):
    path = tmp_path / "sub" / "users.json"
    UserStore(str(path)).register("alice", "password1")
    assert UserStore(str(path)).verify("alice", "password1")
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
