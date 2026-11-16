# SecureChat : spécifications fonctionnelles et de sécurité (version β)

Auteur : Valentin Fernandez. Date : 17/11/2026.

## 1. Objet

SecureChat est une messagerie multipoints : un serveur central et plusieurs clients en ligne
de commande qui partagent un salon de discussion unique. Le but du projet est de livrer une
fonction de sécurité simple mais correctement construite : canal chiffré et authentifié,
comptes protégés, entrées validées, chaîne d'intégration continue avec analyse de sécurité.

Architecture retenue : client lourd - serveur, en Python (bibliothèque standard uniquement).

```
 client CLI ──TLS──┐
 client CLI ──TLS──┼── serveur (1 thread / client) ── data/users.json
 client CLI ──TLS──┘
```

## 2. Spécifications fonctionnelles

| ID | Fonction | Critère d'acceptation |
|---|---|---|
| F1 | Créer un compte | `client alice --register` crée le compte si le nom est libre et valide |
| F2 | Se connecter | avec le bon mot de passe le serveur répond `welcome alice` |
| F3 | Envoyer un message | le message est reçu par tous les utilisateurs connectés, préfixé par l'auteur |
| F4 | Être prévenu des arrivées/départs | `alice joined the chat` / `alice left the chat` diffusés |
| F5 | Quitter | `/quit` ferme proprement la connexion |
| F6 | Messages d'erreur clairs | toute entrée refusée renvoie un message `error` lisible |

Règles sur les données : nom d'utilisateur 3 à 20 caractères `[A-Za-z0-9_]`, mot de passe 8 à
128 caractères, message 1 à 500 caractères sans caractère de contrôle, trame de 4096 octets max.

## 3. Objectifs de sécurité

| ID | Objectif | Mesure | Emplacement |
|---|---|---|---|
| S1 | Confidentialité et intégrité des échanges | TLS ≥ 1.2 | `server.py` `make_server_context`, `client.py` `make_client_context` |
| S2 | Authentifier le serveur | le client vérifie certificat + nom d'hôte (`create_default_context`) | `client.py` `connect` |
| S3 | Authentifier les utilisateurs | login obligatoire avant tout message | `server.py` `authenticate` |
| S4 | Protéger les mots de passe stockés | scrypt (n=2^14, r=8, p=1), sel de 16 octets, fichier en 0600 | `auth.py` |
| S5 | Limiter le brute-force | 3 essais par connexion, comparaison `hmac.compare_digest` | `server.py`, `auth.py` |
| S6 | Ne pas révéler les comptes existants | même message `invalid credentials`, hachage effectué même si l'utilisateur n'existe pas | `auth.py` `verify` |
| S7 | Résister aux entrées malveillantes | validation stricte de chaque champ, taille max des trames | `protocol.py` |
| S8 | Empêcher l'usurpation d'un utilisateur connecté | refus d'une 2e session sur le même compte | `server.py` `authenticate` |
| S9 | Pas de secret dans le code | certificats et base utilisateurs hors dépôt, `.gitignore` | `.gitignore` |
| S10 | Traçabilité | journalisation des connexions et échecs, sans mot de passe | `server.py` |

## 4. Modèle de menace (simplifié, STRIDE)

Actifs : contenu des messages, mots de passe, disponibilité du salon.
Attaquants considérés : quelqu'un sur le même réseau (écoute, interception), un client
malveillant qui envoie des données forgées, un attaquant qui essaie des mots de passe.

| Menace | Exemple | Contre-mesure | Reste à faire |
|---|---|---|---|
| Spoofing | se faire passer pour le serveur | vérification du certificat (S2) | — |
| Spoofing | se connecter avec le compte d'un autre | mots de passe hachés, 3 essais (S4, S5) | limiter par IP, pas seulement par connexion |
| Tampering | modifier un message en transit | TLS (S1) | — |
| Repudiation | nier avoir envoyé un message | le serveur impose l'auteur (`from`) | journaliser les messages ? (à arbitrer avec la vie privée) |
| Information disclosure | lire les messages sur le réseau | TLS (S1) | le serveur voit tout : chiffrement de bout en bout hors périmètre |
| Information disclosure | vol du fichier des comptes | hachage scrypt + droits 0600 | — |
| Denial of service | trames géantes, milliers de connexions | 4096 octets max, 50 clients max, timeout 10 min | client lent bloquant la diffusion, flood de messages |
| Elevation of privilege | injecter des séquences ANSI dans le terminal des autres | caractères de contrôle refusés (S7) + filtrage à l'affichage | — |

## 5. Choix techniques et bibliothèques

- `ssl` (bibliothèque standard, s'appuie sur OpenSSL) : implémentation TLS maintenue, plutôt
  qu'un chiffrement fait maison.
- `hashlib.scrypt` : fonction de dérivation de clé conçue pour les mots de passe, coûteuse en
  mémoire, recommandée par l'OWASP. Pas de dépendance externe à installer.
- `hmac.compare_digest` : comparaison en temps constant.
- `json` pour le protocole : pas de `pickle` ni d'`eval`, rien d'exécutable dans les données.
- Pas de dépendance d'exécution : surface d'attaque réduite, `pip-audit` ne porte que sur les
  outils de développement.

## 6. Cycle de vie

- Code sous Git (GitLab), une branche par ticket, fusion par merge request.
- CI GitLab à chaque push : `ruff` (qualité), `pytest` + couverture, `bandit` (analyse
  statique de sécurité), `pip-audit` (vulnérabilités connues des dépendances). Un échec
  bloque la fusion.
- Versions des outils figées dans `requirements-dev.txt` pour des builds reproductibles.
- Version sémantique : 0.1.0 pour la β, 1.0.0 pour le rendu de janvier.
- Déploiement : génération d'un certificat par serveur (`scripts/gen_cert.sh`), validité
  365 jours, à renouveler. La clé privée ne quitte pas le serveur.
- Les failles remontées par l'audit externe seront saisies comme tickets et corrigées au
  sprint 3.

## 7. Limites connues de la β

- Le serveur déchiffre les messages (pas de chiffrement de bout en bout).
- Certificat auto-signé, distribué à la main aux clients.
- La diffusion se fait sous un verrou : un client qui ne lit plus peut ralentir les autres.
- Pas de limite de débit sur l'envoi de messages.
- Pas de salons multiples ni de messages privés.
