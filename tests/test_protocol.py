import io

import pytest

from securechat import protocol
from securechat.protocol import ProtocolError


def test_encode_decode_roundtrip():
    message = {"type": "msg", "text": "hello é"}
    assert protocol.decode(protocol.encode(message)) == message


def test_encode_rejects_long_message():
    with pytest.raises(ProtocolError):
        protocol.encode({"type": "msg", "text": "a" * protocol.MAX_LINE})


@pytest.mark.parametrize("line", [b"not json\n", b"\xff\xfe\n", b"[1, 2]\n", b'{"text": "x"}\n'])
def test_decode_rejects_bad_input(line):
    with pytest.raises(ProtocolError):
        protocol.decode(line)


def test_read_message_eof_and_too_long():
    assert protocol.read_message(io.BytesIO(b"")) is None
    with pytest.raises(ProtocolError):
        protocol.read_message(io.BytesIO(b"a" * (protocol.MAX_LINE + 10)))


@pytest.mark.parametrize("name", ["bob", "alice_42", "A" * 20])
def test_valid_usernames(name):
    assert protocol.check_username(name) == name


@pytest.mark.parametrize("name", ["ab", "a" * 21, "bob smith", "bob\n", "../etc", None, 42])
def test_invalid_usernames(name):
    with pytest.raises(ProtocolError):
        protocol.check_username(name)


def test_password_length():
    assert protocol.check_password("12345678")
    for bad in ["short", "x" * 129, None]:
        with pytest.raises(ProtocolError):
            protocol.check_password(bad)


def test_text_is_stripped():
    assert protocol.check_text("  hi  ") == "hi"


@pytest.mark.parametrize("text", ["", "   ", "x" * 501, "evil\x1b[2J", "a\nb", 12])
def test_invalid_text(text):
    with pytest.raises(ProtocolError):
        protocol.check_text(text)
