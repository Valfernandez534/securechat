# SecureChat

Messagerie multipoints (salon de discussion commun) en client-serveur, chiffrée en TLS.
Projet « Secure Development - DevSecOps », EPITA APPING2 2026-2027. Version β (0.1.0).

Le serveur accepte plusieurs clients en même temps. Chaque utilisateur crée un compte
(nom + mot de passe), se connecte, et ses messages sont diffusés à tous les connectés.

## Prérequis

- Python 3.10 ou plus récent (aucune dépendance externe à l'exécution)
- `openssl` pour générer le certificat du serveur
- Linux ou macOS (testé sous Linux). À utiliser uniquement sur vos propres machines/VM.

## Installation

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt         # outils de test et d'analyse, optionnels pour l'usage
./scripts/gen_cert.sh                    # crée certs/server.crt et certs/server.key
```

Options du serveur : `--hote`, `--port`, `--certificat`, `--cle`, `--utilisateurs`.

Pour un serveur sur une autre machine que les clients, générer le certificat avec son nom
ou son IP : `./scripts/gen_cert.sh certs mon-serveur.lan`, puis copier **uniquement**
`certs/server.crt` sur les postes clients. La clé `server.key` reste sur le serveur.

## Utilisation

Lancer le serveur (écoute sur 127.0.0.1:5555 par défaut) :

```sh
python -m securechat.server
python -m securechat.server --hote 0.0.0.0 --port 5555   # pour accepter le réseau local
```

Dans un autre terminal, créer un compte puis discuter :

```sh
python -m securechat.client alice --inscription   # première fois
python -m securechat.client alice                 # fois suivantes
```

Le mot de passe est demandé sans écho (8 caractères minimum). On tape ensuite ses messages,
`/quit` pour partir. Options du client : `--hote`, `--port`, `--ca` (certificat du serveur
à utiliser, `certs/server.crt` par défaut).

Exemple de session :

```
Mot de passe :
* bienvenue alice
* tapez vos messages, /quit pour quitter
* alice a rejoint la discussion
* bob a rejoint la discussion
[bob] salut
```

## Organisation du code

| Fichier | Rôle |
|---|---|
| `securechat/protocol.py` | Format des messages (une ligne JSON), limites de taille, validation des entrées |
| `securechat/auth.py` | Comptes utilisateurs : hachage scrypt salé, fichier `data/users.json` en 0600 |
| `securechat/server.py` | Serveur TLS multi-clients (un thread par client), authentification, diffusion |
| `securechat/client.py` | Client en ligne de commande, vérification du certificat serveur |
| `tests/` | Tests unitaires (protocole, auth) et de bout en bout (vrai serveur TLS en local) |

Protocole : chaque message est un objet JSON sur une ligne, 4096 octets maximum.

| Sens | Message |
|---|---|
| client → serveur | `{"type": "register" \| "login", "user": ..., "password": ...}` |
| client → serveur | `{"type": "msg", "text": ...}`, `{"type": "quit"}` |
| serveur → client | `{"type": "ok" \| "error" \| "info", "text": ...}` |
| serveur → client | `{"type": "msg", "from": ..., "text": ...}` |

## Tests et analyse

```sh
pytest --cov=securechat          # tests + couverture
ruff check securechat tests      # style et erreurs courantes
bandit -r securechat             # analyse de sécurité statique
pip-audit -r requirements.txt
```

La même chaîne tourne dans GitHub Actions (`.github/workflows/ci.yml`) à chaque push et
pull request.

## Sécurité

Résumé des mesures (détail et modèle de menace dans `docs/specifications.md`) :

- TLS 1.2 minimum, le client vérifie le certificat et le nom du serveur
- mots de passe hachés avec scrypt et un sel aléatoire par utilisateur, comparaison en temps constant
- 3 tentatives de connexion par session, puis déconnexion
- toutes les entrées réseau sont validées (taille, type, caractères autorisés)
- caractères de contrôle refusés pour empêcher l'injection de séquences d'échappement terminal
- aucun secret dans le code ni dans le dépôt (`certs/` et `data/` sont dans `.gitignore`)

Limites connues de la version β : pas de chiffrement de bout en bout (le serveur voit les
messages en clair), pas d'historique, un client très lent peut ralentir la diffusion.
