import argparse
import logging
import socket
import ssl
import threading

from securechat import protocol
from securechat.auth import StockageUtilisateurs
from securechat.protocol import ErreurProtocole

journal = logging.getLogger("securechat.server")

CLIENTS_MAX = 50
TENTATIVES_MAX = 3
DELAI_INACTIVITE = 600


def creer_contexte_serveur(certificat, cle):
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.minimum_version = ssl.TLSVersion.TLSv1_2
    contexte.load_cert_chain(certificat, cle)
    return contexte


class ServeurMessagerie:
    def __init__(self, hote, port, contexte, utilisateurs):
        self.contexte = contexte
        self.utilisateurs = utilisateurs
        self.clients = {}
        self.verrou = threading.Lock()
        self.socket = socket.create_server((hote, port))
        self.socket.settimeout(1.0)
        self.port = self.socket.getsockname()[1]
        self.actif = False

    def demarrer(self):
        self.actif = True
        journal.info("ecoute sur le port %d", self.port)
        while self.actif:
            try:
                brut, adresse = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            fil = threading.Thread(target=self.gerer_client, args=(brut, adresse), daemon=True)
            fil.start()

    def arreter(self):
        self.actif = False
        self.socket.close()

    def envoyer(self, connexion, message):
        with self.verrou:
            connexion.sendall(protocol.encoder(message))

    def diffuser(self, message):
        donnees = protocol.encoder(message)
        with self.verrou:
            for nom, connexion in list(self.clients.items()):
                try:
                    connexion.sendall(donnees)
                except OSError:
                    journal.warning("envoi impossible a %s, client retire", nom)
                    del self.clients[nom]

    def gerer_client(self, brut, adresse):
        brut.settimeout(DELAI_INACTIVITE)
        try:
            connexion = self.contexte.wrap_socket(brut, server_side=True)
        except (ssl.SSLError, OSError) as e:
            journal.warning("echec de la negociation TLS depuis %s : %s", adresse[0], e)
            brut.close()
            return

        nom = None
        try:
            lecteur = connexion.makefile("rb")
            nom = self.authentifier(connexion, lecteur, adresse)
            if nom is None:
                return
            journal.info("%s connecte depuis %s", nom, adresse[0])
            self.diffuser({"type": "info", "text": f"{nom} a rejoint la discussion"})
            self.boucle_discussion(connexion, lecteur, nom)
        except OSError as e:
            journal.info("connexion avec %s fermee : %s", adresse[0], e)
        finally:
            if nom is not None:
                with self.verrou:
                    self.clients.pop(nom, None)
                journal.info("%s deconnecte", nom)
                self.diffuser({"type": "info", "text": f"{nom} a quitte la discussion"})
            connexion.close()

    def authentifier(self, connexion, lecteur, adresse):
        for _ in range(TENTATIVES_MAX):
            try:
                message = protocol.lire_message(lecteur)
                if message is None:
                    return None
                if message["type"] not in ("login", "register"):
                    raise ErreurProtocole("connexion requise")
                nom = protocol.verifier_nom_utilisateur(message.get("user"))
                mot_de_passe = protocol.verifier_mot_de_passe(message.get("password"))
            except ErreurProtocole as e:
                self.envoyer(connexion, {"type": "error", "text": str(e)})
                continue

            if message["type"] == "register":
                if not self.utilisateurs.inscrire(nom, mot_de_passe):
                    self.envoyer(connexion, {"type": "error", "text": "nom deja utilise"})
                    continue
                journal.info("nouvel utilisateur %s inscrit depuis %s", nom, adresse[0])
            elif not self.utilisateurs.verifier(nom, mot_de_passe):
                journal.warning("echec de connexion pour %s depuis %s", nom, adresse[0])
                self.envoyer(connexion, {"type": "error", "text": "identifiants invalides"})
                continue

            with self.verrou:
                if nom in self.clients:
                    erreur = "utilisateur deja connecte"
                elif len(self.clients) >= CLIENTS_MAX:
                    erreur = "serveur plein"
                else:
                    erreur = None
                    self.clients[nom] = connexion
            if erreur:
                self.envoyer(connexion, {"type": "error", "text": erreur})
                continue
            self.envoyer(connexion, {"type": "ok", "text": f"bienvenue {nom}"})
            return nom

        self.envoyer(connexion, {"type": "error", "text": "trop de tentatives"})
        return None

    def boucle_discussion(self, connexion, lecteur, nom):
        while True:
            try:
                message = protocol.lire_message(lecteur)
                if message is None or message["type"] == "quit":
                    return
                if message["type"] != "msg":
                    raise ErreurProtocole("type de message inconnu")
                texte = protocol.verifier_texte(message.get("text"))
            except ErreurProtocole as e:
                self.envoyer(connexion, {"type": "error", "text": str(e)})
                continue
            self.diffuser({"type": "msg", "from": nom, "text": texte})


def main():
    parser = argparse.ArgumentParser(description="Serveur de messagerie securisee (TLS)")
    parser.add_argument("--hote", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--certificat", default="certs/server.crt")
    parser.add_argument("--cle", default="certs/server.key")
    parser.add_argument("--utilisateurs", default="data/users.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        contexte = creer_contexte_serveur(args.certificat, args.cle)
    except (OSError, ssl.SSLError) as e:
        parser.error(f"impossible de charger le certificat ou la cle : {e}")

    serveur = ServeurMessagerie(
        args.hote, args.port, contexte, StockageUtilisateurs(args.utilisateurs)
    )
    try:
        serveur.demarrer()
    except KeyboardInterrupt:
        journal.info("arret du serveur")
    finally:
        serveur.arreter()


if __name__ == "__main__":
    main()
