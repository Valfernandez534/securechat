import hashlib
import hmac
import json
import os
import threading

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
TAILLE_SEL = 16


def hacher_mot_de_passe(mot_de_passe, sel):
    return hashlib.scrypt(
        mot_de_passe.encode("utf-8"), salt=sel, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


class StockageUtilisateurs:
    def __init__(self, chemin):
        self.chemin = chemin
        self.verrou = threading.Lock()
        self.utilisateurs = {}
        if os.path.exists(chemin):
            with open(chemin, encoding="utf-8") as f:
                self.utilisateurs = json.load(f)

    def inscrire(self, nom, mot_de_passe):
        with self.verrou:
            if nom in self.utilisateurs:
                return False
            sel = os.urandom(TAILLE_SEL)
            self.utilisateurs[nom] = {
                "sel": sel.hex(),
                "hash": hacher_mot_de_passe(mot_de_passe, sel).hex(),
            }
            self.sauvegarder()
            return True

    def verifier(self, nom, mot_de_passe):
        utilisateur = self.utilisateurs.get(nom)
        if utilisateur is None:
            hacher_mot_de_passe(mot_de_passe, bytes(TAILLE_SEL))
            return False
        calcule = hacher_mot_de_passe(mot_de_passe, bytes.fromhex(utilisateur["sel"]))
        return hmac.compare_digest(calcule, bytes.fromhex(utilisateur["hash"]))

    def sauvegarder(self):
        dossier = os.path.dirname(self.chemin)
        if dossier:
            os.makedirs(dossier, exist_ok=True)
        temporaire = self.chemin + ".tmp"
        fd = os.open(temporaire, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.utilisateurs, f, indent=2)
        os.replace(temporaire, self.chemin)
