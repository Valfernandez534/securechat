import io

import pytest

from securechat import protocol
from securechat.protocol import ErreurProtocole


def test_aller_retour_encodage():
    message = {"type": "msg", "text": "bonjour é"}
    assert protocol.decoder(protocol.encoder(message)) == message


def test_encodage_refuse_message_trop_long():
    with pytest.raises(ErreurProtocole):
        protocol.encoder({"type": "msg", "text": "a" * protocol.TAILLE_MAX_LIGNE})


@pytest.mark.parametrize("ligne", [b"pas json\n", b"\xff\xfe\n", b"[1, 2]\n", b'{"text": "x"}\n'])
def test_decodage_refuse_entree_invalide(ligne):
    with pytest.raises(ErreurProtocole):
        protocol.decoder(ligne)


def test_lecture_fin_de_flux_et_ligne_trop_longue():
    assert protocol.lire_message(io.BytesIO(b"")) is None
    with pytest.raises(ErreurProtocole):
        protocol.lire_message(io.BytesIO(b"a" * (protocol.TAILLE_MAX_LIGNE + 10)))


@pytest.mark.parametrize("nom", ["bob", "alice_42", "A" * 20])
def test_noms_valides(nom):
    assert protocol.verifier_nom_utilisateur(nom) == nom


@pytest.mark.parametrize("nom", ["ab", "a" * 21, "bob smith", "bob\n", "../etc", None, 42])
def test_noms_invalides(nom):
    with pytest.raises(ErreurProtocole):
        protocol.verifier_nom_utilisateur(nom)


def test_longueur_mot_de_passe():
    assert protocol.verifier_mot_de_passe("12345678")
    for mauvais in ["court", "x" * 129, None]:
        with pytest.raises(ErreurProtocole):
            protocol.verifier_mot_de_passe(mauvais)


def test_texte_nettoye_des_espaces():
    assert protocol.verifier_texte("  salut  ") == "salut"


@pytest.mark.parametrize("texte", ["", "   ", "x" * 501, "evil\x1b[2J", "a\nb", 12])
def test_textes_invalides(texte):
    with pytest.raises(ErreurProtocole):
        protocol.verifier_texte(texte)
