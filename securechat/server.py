import argparse
import logging
import socket
import ssl
import threading

from securechat import protocol
from securechat.auth import UserStore
from securechat.protocol import ProtocolError

log = logging.getLogger("securechat.server")

MAX_CLIENTS = 50
MAX_LOGIN_ATTEMPTS = 3
IDLE_TIMEOUT = 600


def make_server_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    return context


class ChatServer:
    def __init__(self, host, port, context, users):
        self.context = context
        self.users = users
        self.clients = {}
        self.lock = threading.Lock()
        self.sock = socket.create_server((host, port))
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.running = False

    def serve_forever(self):
        self.running = True
        log.info("listening on port %d", self.port)
        while self.running:
            try:
                raw, addr = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self.handle_client, args=(raw, addr), daemon=True)
            thread.start()

    def shutdown(self):
        self.running = False
        self.sock.close()

    def send(self, conn, message):
        # the lock avoids two threads writing on the same TLS socket at once
        with self.lock:
            conn.sendall(protocol.encode(message))

    def broadcast(self, message):
        data = protocol.encode(message)
        with self.lock:
            for name, conn in list(self.clients.items()):
                try:
                    conn.sendall(data)
                except OSError:
                    log.warning("could not send to %s, dropping client", name)
                    del self.clients[name]

    def handle_client(self, raw, addr):
        raw.settimeout(IDLE_TIMEOUT)
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as e:
            log.warning("TLS handshake failed from %s: %s", addr[0], e)
            raw.close()
            return

        username = None
        try:
            reader = conn.makefile("rb")
            username = self.authenticate(conn, reader, addr)
            if username is None:
                return
            log.info("%s logged in from %s", username, addr[0])
            self.broadcast({"type": "info", "text": f"{username} joined the chat"})
            self.chat_loop(conn, reader, username)
        except OSError as e:
            log.info("connection with %s closed: %s", addr[0], e)
        finally:
            if username is not None:
                with self.lock:
                    self.clients.pop(username, None)
                log.info("%s disconnected", username)
                self.broadcast({"type": "info", "text": f"{username} left the chat"})
            conn.close()

    def authenticate(self, conn, reader, addr):
        for _ in range(MAX_LOGIN_ATTEMPTS):
            try:
                message = protocol.read_message(reader)
                if message is None:
                    return None
                if message["type"] not in ("login", "register"):
                    raise ProtocolError("login required")
                name = protocol.check_username(message.get("user"))
                password = protocol.check_password(message.get("password"))
            except ProtocolError as e:
                self.send(conn, {"type": "error", "text": str(e)})
                continue

            if message["type"] == "register":
                if not self.users.register(name, password):
                    self.send(conn, {"type": "error", "text": "username already taken"})
                    continue
                log.info("new user %s registered from %s", name, addr[0])
            elif not self.users.verify(name, password):
                log.warning("failed login for %s from %s", name, addr[0])
                self.send(conn, {"type": "error", "text": "invalid credentials"})
                continue

            with self.lock:
                if name in self.clients:
                    error = "user already connected"
                elif len(self.clients) >= MAX_CLIENTS:
                    error = "server full"
                else:
                    error = None
                    self.clients[name] = conn
            if error:
                self.send(conn, {"type": "error", "text": error})
                continue
            self.send(conn, {"type": "ok", "text": f"welcome {name}"})
            return name

        self.send(conn, {"type": "error", "text": "too many attempts"})
        return None

    def chat_loop(self, conn, reader, username):
        while True:
            try:
                message = protocol.read_message(reader)
                if message is None or message["type"] == "quit":
                    return
                if message["type"] != "msg":
                    raise ProtocolError("unknown message type")
                text = protocol.check_text(message.get("text"))
            except ProtocolError as e:
                self.send(conn, {"type": "error", "text": str(e)})
                continue
            self.broadcast({"type": "msg", "from": username, "text": text})


def main():
    parser = argparse.ArgumentParser(description="Secure chat server (TLS)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--cert", default="certs/server.crt")
    parser.add_argument("--key", default="certs/server.key")
    parser.add_argument("--users", default="data/users.json")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        context = make_server_context(args.cert, args.key)
    except (OSError, ssl.SSLError) as e:
        parser.error(f"cannot load certificate/key: {e}")

    server = ChatServer(args.host, args.port, context, UserStore(args.users))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("stopping server")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
