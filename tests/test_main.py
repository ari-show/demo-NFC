import argparse
import time

import nfc
import pytest

import main


def test_safe_replaces_control_characters():
    assert main.safe("a\x1b[31mb" + chr(0x202E) + "c\x07") == "a.[31mb.c."


def test_safe_keeps_printable_text():
    assert main.safe("カード abc 123") == "カード abc 123"


def test_positive_int():
    assert main.positive_int("3") == 3
    with pytest.raises(argparse.ArgumentTypeError):
        main.positive_int("0")


class FakeTag:
    def __init__(self, blocks):
        self.blocks = blocks

    def read_without_encryption(self, services, block_codes):
        index = block_codes[0].number
        if index >= len(self.blocks):
            raise nfc.tag.TagCommandError(0)
        return self.blocks[index]


def test_read_service_joins_blocks_and_extracts_ascii(capsys):
    tag = FakeTag([b"\x00" * 14 + b"AB", b"CD" + b"\x00" * 14])
    data = main.read_service(tag, "svc", 8, time.monotonic() + 10)
    assert len(data) == 32
    assert "'ABCD'" in capsys.readouterr().out


def test_read_service_respects_max_blocks(capsys):
    tag = FakeTag([b"\x00" * 16] * 10)
    data = main.read_service(tag, "svc", 3, time.monotonic() + 10)
    assert len(data) == 48
    assert "最大3ブロック" in capsys.readouterr().out


def test_read_service_stops_at_deadline():
    tag = FakeTag([b"\x00" * 16] * 10)
    assert main.read_service(tag, "svc", 5, time.monotonic() - 1) == b""
