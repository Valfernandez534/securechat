"""End-to-end tests: real server and clients over TLS on localhost."""

import socket
import ssl

import pytest

from securechat import protocol
from securechat.client import clean, connect, format_message, login


def open_client(server, certs):
    conn = connect("localhost", server.port, certs[0])
    conn.settimeout(5)
    return conn, conn.makefile("rb")


def test_register_login_and_broadcast(server, certs):
    alice, alice_in = open_client(server, certs)
    assert login(alice, alice_in, "alice", "alicepass", register=True)[0]
    assert protocol.read_message(alice_in)["text"] == "alice joined the chat"

    bob, bob_in = open_client(server, certs)
    assert login(bob, bob_in, "bob", "bobpass12", register=True)[0]
    assert protocol.read_message(alice_in)["text"] == "bob joined the chat"
    protocol.read_message(bob_in)

    alice.sendall(protocol.encode({"type": "msg", "text": "hi bob"}))
    for reader in (alice_in, bob_in):
        assert protocol.read_message(reader) == {"type": "msg", "from": "alice", "text": "hi bob"}

    bob.sendall(protocol.encode({"type": "quit"}))
    assert protocol.read_message(alice_in)["text"] == "bob left the chat"
    alice.close()
    bob.close()


def test_wrong_password_then_lockout(server, certs):
    server.users.register("carol", "carolpass")
    conn, reader = open_client(server, certs)
    for _ in range(2):
        assert login(conn, reader, "carol", "badpassword") == (False, "invalid credentials")
    assert login(conn, reader, "carol", "badpassword") == (False, "invalid credentials")
    assert protocol.read_message(reader)["text"] == "too many attempts"
    assert protocol.read_message(reader) is None
    conn.close()


def test_message_before_login_is_refused(server, certs):
    conn, reader = open_client(server, certs)
    conn.sendall(protocol.encode({"type": "msg", "text": "hello"}))
    assert protocol.read_message(reader) == {"type": "error", "text": "login required"}
    conn.close()


def test_same_user_cannot_connect_twice(server, certs):
    first, first_in = open_client(server, certs)
    assert login(first, first_in, "dave", "davepass1", register=True)[0]
    second, second_in = open_client(server, certs)
    assert login(second, second_in, "dave", "davepass1") == (False, "user already connected")
    first.close()
    second.close()


def test_invalid_message_is_rejected(server, certs):
    conn, reader = open_client(server, certs)
    login(conn, reader, "eve", "evepass12", register=True)
    protocol.read_message(reader)
    conn.sendall(protocol.encode({"type": "msg", "text": "\x1b[2Jcleared"}))
    assert protocol.read_message(reader)["type"] == "error"
    conn.sendall(b"garbage\n")
    assert protocol.read_message(reader) == {"type": "error", "text": "invalid json"}
    conn.close()


def test_plain_tcp_client_is_refused(server):
    with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
        raw.sendall(protocol.encode({"type": "login", "user": "mallory", "password": "password"}))
        try:
            answer = raw.recv(1024)
        except ConnectionResetError:
            answer = b""
    # the server only speaks TLS: no JSON answer, at most a TLS alert or a reset
    assert not answer.startswith(b"{")
    assert "mallory" not in server.clients


def test_client_rejects_unknown_certificate(server):
    # without our CA file, the system CAs do not trust the self-signed certificate
    with pytest.raises(ssl.SSLCertVerificationError):
        connect("localhost", server.port, None)


def test_format_message_strips_control_chars():
    assert clean("ok\x1b[31m") == "ok[31m"
    assert format_message({"type": "msg", "from": "bob", "text": "hi"}) == "[bob] hi"
    assert format_message({"type": "error", "text": "bad"}) == "! bad"
