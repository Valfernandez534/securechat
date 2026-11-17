import socket
import ssl

import pytest

from securechat import protocol
from securechat.client import connecter, connexion_compte, formater_message, nettoyer_affichage


def ouvrir_client(serveur, certificats):
    connexion = connecter("localhost", serveur.port, certificats[0])
    connexion.settimeout(5)
    return connexion, connexion.makefile("rb")


def test_inscription_connexion_et_diffusion(serveur, certificats):
    alice, alice_in = ouvrir_client(serveur, certificats)
    assert connexion_compte(alice, alice_in, "alice", "alicepass", inscription=True)[0]
    assert protocol.lire_message(alice_in)["text"] == "alice a rejoint la discussion"

    bob, bob_in = ouvrir_client(serveur, certificats)
    assert connexion_compte(bob, bob_in, "bob", "bobpass12", inscription=True)[0]
    assert protocol.lire_message(alice_in)["text"] == "bob a rejoint la discussion"
    protocol.lire_message(bob_in)

    alice.sendall(protocol.encoder({"type": "msg", "text": "salut bob"}))
    for lecteur in (alice_in, bob_in):
        attendu = {"type": "msg", "from": "alice", "text": "salut bob"}
        assert protocol.lire_message(lecteur) == attendu

    bob.sendall(protocol.encoder({"type": "quit"}))
    assert protocol.lire_message(alice_in)["text"] == "bob a quitte la discussion"
    alice.close()
    bob.close()


def test_mauvais_mot_de_passe_puis_blocage(serveur, certificats):
    serveur.utilisateurs.inscrire("carol", "carolpass")
    connexion, lecteur = ouvrir_client(serveur, certificats)
    for _ in range(3):
        resultat = connexion_compte(connexion, lecteur, "carol", "badpassword")
        assert resultat == (False, "identifiants invalides")
    assert protocol.lire_message(lecteur)["text"] == "trop de tentatives"
    assert protocol.lire_message(lecteur) is None
    connexion.close()


def test_message_avant_connexion_refuse(serveur, certificats):
    connexion, lecteur = ouvrir_client(serveur, certificats)
    connexion.sendall(protocol.encoder({"type": "msg", "text": "bonjour"}))
    assert protocol.lire_message(lecteur) == {"type": "error", "text": "connexion requise"}
    connexion.close()


def test_meme_utilisateur_deux_fois_refuse(serveur, certificats):
    premier, premier_in = ouvrir_client(serveur, certificats)
    assert connexion_compte(premier, premier_in, "dave", "davepass1", inscription=True)[0]
    second, second_in = ouvrir_client(serveur, certificats)
    resultat = connexion_compte(second, second_in, "dave", "davepass1")
    assert resultat == (False, "utilisateur deja connecte")
    premier.close()
    second.close()


def test_message_invalide_rejete(serveur, certificats):
    connexion, lecteur = ouvrir_client(serveur, certificats)
    connexion_compte(connexion, lecteur, "eve", "evepass12", inscription=True)
    protocol.lire_message(lecteur)
    connexion.sendall(protocol.encoder({"type": "msg", "text": "\x1b[2Jefface"}))
    assert protocol.lire_message(lecteur)["type"] == "error"
    connexion.sendall(b"n'importe quoi\n")
    assert protocol.lire_message(lecteur) == {"type": "error", "text": "json invalide"}
    connexion.close()


def test_client_tcp_sans_tls_refuse(serveur):
    with socket.create_connection(("127.0.0.1", serveur.port), timeout=5) as brut:
        brut.sendall(
            protocol.encoder({"type": "login", "user": "mallory", "password": "password"})
        )
        try:
            reponse = brut.recv(1024)
        except ConnectionResetError:
            reponse = b""
    assert not reponse.startswith(b"{")
    assert "mallory" not in serveur.clients


def test_client_refuse_certificat_inconnu(serveur):
    with pytest.raises(ssl.SSLCertVerificationError):
        connecter("localhost", serveur.port, None)


def test_formatage_supprime_caracteres_de_controle():
    assert nettoyer_affichage("ok\x1b[31m") == "ok[31m"
    assert formater_message({"type": "msg", "from": "bob", "text": "salut"}) == "[bob] salut"
    assert formater_message({"type": "error", "text": "erreur"}) == "! erreur"
