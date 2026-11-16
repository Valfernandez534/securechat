import hashlib
import hmac
import json
import os
import threading

# scrypt cost parameters (OWASP minimum recommendation)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16


def hash_password(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )


class UserStore:
    """Users saved in a JSON file: {username: {"salt": hex, "hash": hex}}."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.users = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.users = json.load(f)

    def register(self, username, password):
        with self.lock:
            if username in self.users:
                return False
            salt = os.urandom(SALT_SIZE)
            self.users[username] = {
                "salt": salt.hex(),
                "hash": hash_password(password, salt).hex(),
            }
            self._save()
            return True

    def verify(self, username, password):
        user = self.users.get(username)
        if user is None:
            # hash anyway so the response time does not tell if the user exists
            hash_password(password, bytes(SALT_SIZE))
            return False
        computed = hash_password(password, bytes.fromhex(user["salt"]))
        return hmac.compare_digest(computed, bytes.fromhex(user["hash"]))

    def _save(self):
        folder = os.path.dirname(self.path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.users, f, indent=2)
        os.replace(tmp, self.path)
