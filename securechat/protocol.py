"""Wire format: one JSON object per line, UTF-8, max MAX_LINE bytes."""

import json
import re

MAX_LINE = 4096
MAX_TEXT = 500
MIN_PASSWORD = 8
MAX_PASSWORD = 128
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")


class ProtocolError(Exception):
    pass


def encode(message):
    data = json.dumps(message).encode("utf-8") + b"\n"
    if len(data) > MAX_LINE:
        raise ProtocolError("message too long")
    return data


def decode(line):
    if len(line) > MAX_LINE:
        raise ProtocolError("message too long")
    try:
        message = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("invalid json") from None
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ProtocolError("missing message type")
    return message


def read_message(reader):
    """Read one message from a binary file object. Returns None on EOF."""
    line = reader.readline(MAX_LINE + 1)
    if not line:
        return None
    return decode(line)


def check_username(name):
    if not isinstance(name, str) or not USERNAME_RE.fullmatch(name):
        raise ProtocolError("username must be 3-20 letters, digits or _")
    return name


def check_password(password):
    if not isinstance(password, str):
        raise ProtocolError("invalid password")
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise ProtocolError(f"password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
    return password


def check_text(text):
    if not isinstance(text, str):
        raise ProtocolError("invalid text")
    text = text.strip()
    if not 1 <= len(text) <= MAX_TEXT:
        raise ProtocolError(f"text must be 1-{MAX_TEXT} characters")
    # control characters could be used to inject terminal escape sequences
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ProtocolError("control characters are not allowed")
    return text
