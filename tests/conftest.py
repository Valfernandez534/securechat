import subprocess
import threading

import pytest

from securechat.auth import UserStore
from securechat.server import ChatServer, make_server_context


@pytest.fixture(scope="session")
def certs(tmp_path_factory):
    folder = tmp_path_factory.mktemp("certs")
    cert, key = folder / "server.crt", folder / "server.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


@pytest.fixture
def server(certs, tmp_path):
    cert, key = certs
    users = UserStore(str(tmp_path / "users.json"))
    srv = ChatServer("127.0.0.1", 0, make_server_context(cert, key), users)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    thread.join(timeout=5)
