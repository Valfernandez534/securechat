import json
import re

TAILLE_MAX_LIGNE = 4096
TAILLE_MAX_TEXTE = 500
MOT_DE_PASSE_MIN = 8
MOT_DE_PASSE_MAX = 128
MOTIF_NOM_UTILISATEUR = re.compile(r"[A-Za-z0-9_]{3,20}")


class ErreurProtocole(Exception):
    pass


def encoder(message):
    donnees = json.dumps(message).encode("utf-8") + b"\n"
    if len(donnees) > TAILLE_MAX_LIGNE:
        raise ErreurProtocole("message trop long")
    return donnees


def decoder(ligne):
    if len(ligne) > TAILLE_MAX_LIGNE:
        raise ErreurProtocole("message trop long")
    try:
        message = json.loads(ligne.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ErreurProtocole("json invalide") from None
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ErreurProtocole("type de message manquant")
    return message


def lire_message(lecteur):
    ligne = lecteur.readline(TAILLE_MAX_LIGNE + 1)
    if not ligne:
        return None
    return decoder(ligne)


def verifier_nom_utilisateur(nom):
    if not isinstance(nom, str) or not MOTIF_NOM_UTILISATEUR.fullmatch(nom):
        raise ErreurProtocole("le nom doit faire 3 a 20 caracteres (lettres, chiffres ou _)")
    return nom


def verifier_mot_de_passe(mot_de_passe):
    if not isinstance(mot_de_passe, str):
        raise ErreurProtocole("mot de passe invalide")
    if not MOT_DE_PASSE_MIN <= len(mot_de_passe) <= MOT_DE_PASSE_MAX:
        raise ErreurProtocole(
            f"le mot de passe doit faire {MOT_DE_PASSE_MIN} a {MOT_DE_PASSE_MAX} caracteres"
        )
    return mot_de_passe


def verifier_texte(texte):
    if not isinstance(texte, str):
        raise ErreurProtocole("texte invalide")
    texte = texte.strip()
    if not 1 <= len(texte) <= TAILLE_MAX_TEXTE:
        raise ErreurProtocole(f"le texte doit faire 1 a {TAILLE_MAX_TEXTE} caracteres")
    if any(ord(c) < 32 or ord(c) == 127 for c in texte):
        raise ErreurProtocole("caracteres de controle interdits")
    return texte
