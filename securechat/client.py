import argparse
import getpass
import socket
import ssl
import sys
import threading

from securechat import protocol
from securechat.protocol import ProtocolError


def make_client_context(cafile):
    # verifies the server certificate and hostname
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def connect(host, port, cafile):
    context = make_client_context(cafile)
    raw = socket.create_connection((host, port), timeout=10)
    try:
        conn = context.wrap_socket(raw, server_hostname=host)
    except (ssl.SSLError, OSError):
        raw.close()
        raise
    conn.settimeout(None)
    return conn


def login(conn, reader, user, password, register=False):
    """Returns (ok, text) with the server answer."""
    kind = "register" if register else "login"
    conn.sendall(protocol.encode({"type": kind, "user": user, "password": password}))
    answer = protocol.read_message(reader)
    if answer is None:
        return False, "connection closed by server"
    return answer["type"] == "ok", answer.get("text", "")


def clean(text):
    # defence in depth: never print raw control characters coming from the network
    return "".join(c for c in str(text) if c.isprintable())


def format_message(message):
    if message["type"] == "msg":
        return f"[{clean(message.get('from'))}] {clean(message.get('text'))}"
    if message["type"] == "error":
        return f"! {clean(message.get('text'))}"
    return f"* {clean(message.get('text'))}"


def receive_loop(reader):
    while True:
        try:
            message = protocol.read_message(reader)
        except ProtocolError:
            continue
        except OSError:
            break
        if message is None:
            break
        print(format_message(message))
    print("* disconnected from server")


def main():
    parser = argparse.ArgumentParser(description="Secure chat client (TLS)")
    parser.add_argument("user")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--ca", default="certs/server.crt", help="server certificate to trust")
    parser.add_argument("--register", action="store_true", help="create the account first")
    args = parser.parse_args()

    try:
        protocol.check_username(args.user)
    except ProtocolError as e:
        parser.error(str(e))
    password = getpass.getpass("Password: ")

    try:
        conn = connect(args.host, args.port, args.ca)
    except ssl.SSLCertVerificationError as e:
        sys.exit(f"server certificate rejected: {e.verify_message}")
    except (OSError, ssl.SSLError) as e:
        sys.exit(f"cannot connect to {args.host}:{args.port}: {e}")

    reader = conn.makefile("rb")
    ok, text = login(conn, reader, args.user, password, args.register)
    print(("* " if ok else "! ") + clean(text))
    if not ok:
        conn.close()
        sys.exit(1)

    threading.Thread(target=receive_loop, args=(reader,), daemon=True).start()
    print("* type your messages, /quit to leave")
    try:
        for line in sys.stdin:
            line = line.strip()
            if line == "/quit":
                break
            if not line:
                continue
            try:
                text = protocol.check_text(line)
            except ProtocolError as e:
                print(f"! {e}")
                continue
            conn.sendall(protocol.encode({"type": "msg", "text": text}))
        conn.sendall(protocol.encode({"type": "quit"}))
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    main()
