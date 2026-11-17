import subprocess
import threading

import pytest

from securechat.auth import StockageUtilisateurs
from securechat.server import ServeurMessagerie, creer_contexte_serveur


@pytest.fixture(scope="session")
def certificats(tmp_path_factory):
    dossier = tmp_path_factory.mktemp("certs")
    certificat, cle = dossier / "server.crt", dossier / "server.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cle), "-out", str(certificat), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(certificat), str(cle)


@pytest.fixture
def serveur(certificats, tmp_path):
    certificat, cle = certificats
    utilisateurs = StockageUtilisateurs(str(tmp_path / "users.json"))
    srv = ServeurMessagerie(
        "127.0.0.1", 0, creer_contexte_serveur(certificat, cle), utilisateurs
    )
    fil = threading.Thread(target=srv.demarrer, daemon=True)
    fil.start()
    yield srv
    srv.arreter()
    fil.join(timeout=5)
