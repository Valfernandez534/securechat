import json
import os
import stat

from securechat.auth import StockageUtilisateurs


def test_inscription_et_verification(tmp_path):
    stockage = StockageUtilisateurs(str(tmp_path / "users.json"))
    assert stockage.inscrire("alice", "correct horse")
    assert stockage.verifier("alice", "correct horse")
    assert not stockage.verifier("alice", "mauvais mot de passe")
    assert not stockage.verifier("personne", "correct horse")


def test_double_inscription(tmp_path):
    stockage = StockageUtilisateurs(str(tmp_path / "users.json"))
    assert stockage.inscrire("alice", "password1")
    assert not stockage.inscrire("alice", "password2")
    assert stockage.verifier("alice", "password1")


def test_mot_de_passe_non_stocke_en_clair(tmp_path):
    chemin = tmp_path / "users.json"
    StockageUtilisateurs(str(chemin)).inscrire("alice", "mon secret")
    contenu = chemin.read_text()
    assert "mon secret" not in contenu
    assert set(json.loads(contenu)["alice"]) == {"sel", "hash"}


def test_meme_mot_de_passe_hash_different(tmp_path):
    stockage = StockageUtilisateurs(str(tmp_path / "users.json"))
    stockage.inscrire("alice", "meme mot de passe")
    stockage.inscrire("bob", "meme mot de passe")
    assert stockage.utilisateurs["alice"]["hash"] != stockage.utilisateurs["bob"]["hash"]


def test_stockage_recharge_et_prive(tmp_path):
    chemin = tmp_path / "sub" / "users.json"
    StockageUtilisateurs(str(chemin)).inscrire("alice", "password1")
    assert StockageUtilisateurs(str(chemin)).verifier("alice", "password1")
    if os.name == "posix":
        assert stat.S_IMODE(chemin.stat().st_mode) == 0o600
