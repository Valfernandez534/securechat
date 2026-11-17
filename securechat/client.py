import argparse
import getpass
import socket
import ssl
import sys
import threading

from securechat import protocol
from securechat.protocol import ErreurProtocole


def creer_contexte_client(fichier_ca):
    contexte = ssl.create_default_context(cafile=fichier_ca)
    contexte.minimum_version = ssl.TLSVersion.TLSv1_2
    return contexte


def connecter(hote, port, fichier_ca):
    contexte = creer_contexte_client(fichier_ca)
    brut = socket.create_connection((hote, port), timeout=10)
    try:
        connexion = contexte.wrap_socket(brut, server_hostname=hote)
    except (ssl.SSLError, OSError):
        brut.close()
        raise
    connexion.settimeout(None)
    return connexion


def connexion_compte(connexion, lecteur, nom, mot_de_passe, inscription=False):
    genre = "register" if inscription else "login"
    connexion.sendall(protocol.encoder({"type": genre, "user": nom, "password": mot_de_passe}))
    reponse = protocol.lire_message(lecteur)
    if reponse is None:
        return False, "connexion fermee par le serveur"
    return reponse["type"] == "ok", reponse.get("text", "")


def nettoyer_affichage(texte):
    return "".join(c for c in str(texte) if c.isprintable())


def formater_message(message):
    if message["type"] == "msg":
        auteur = nettoyer_affichage(message.get("from"))
        return f"[{auteur}] {nettoyer_affichage(message.get('text'))}"
    if message["type"] == "error":
        return f"! {nettoyer_affichage(message.get('text'))}"
    return f"* {nettoyer_affichage(message.get('text'))}"


def boucle_reception(lecteur):
    while True:
        try:
            message = protocol.lire_message(lecteur)
        except ErreurProtocole:
            continue
        except OSError:
            break
        if message is None:
            break
        print(formater_message(message))
    print("* deconnecte du serveur")


def main():
    parser = argparse.ArgumentParser(description="Client de messagerie securisee (TLS)")
    parser.add_argument("utilisateur")
    parser.add_argument("--hote", default="localhost")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--ca", default="certs/server.crt", help="certificat du serveur")
    parser.add_argument("--inscription", action="store_true", help="creer le compte d'abord")
    args = parser.parse_args()

    try:
        protocol.verifier_nom_utilisateur(args.utilisateur)
    except ErreurProtocole as e:
        parser.error(str(e))
    mot_de_passe = getpass.getpass("Mot de passe : ")

    try:
        connexion = connecter(args.hote, args.port, args.ca)
    except ssl.SSLCertVerificationError as e:
        sys.exit(f"certificat du serveur refuse : {e.verify_message}")
    except (OSError, ssl.SSLError) as e:
        sys.exit(f"connexion impossible a {args.hote}:{args.port} : {e}")

    lecteur = connexion.makefile("rb")
    ok, texte = connexion_compte(
        connexion, lecteur, args.utilisateur, mot_de_passe, args.inscription
    )
    print(("* " if ok else "! ") + nettoyer_affichage(texte))
    if not ok:
        connexion.close()
        sys.exit(1)

    threading.Thread(target=boucle_reception, args=(lecteur,), daemon=True).start()
    print("* tapez vos messages, /quit pour quitter")
    try:
        for ligne in sys.stdin:
            ligne = ligne.strip()
            if ligne == "/quit":
                break
            if not ligne:
                continue
            try:
                texte = protocol.verifier_texte(ligne)
            except ErreurProtocole as e:
                print(f"! {e}")
                continue
            connexion.sendall(protocol.encoder({"type": "msg", "text": texte}))
        connexion.sendall(protocol.encoder({"type": "quit"}))
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        connexion.close()


if __name__ == "__main__":
    main()
