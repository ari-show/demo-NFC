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
    data = main.read_service(tag, "svc", 8, time.monotonic() + 10, reveal=True)
    assert len(data) == 32
    assert "'ABCD'" in capsys.readouterr().out


def test_read_service_hides_contents_by_default(capsys):
    tag = FakeTag([b"\x00" * 14 + b"AB", b"CD" + b"\x00" * 14])
    data = main.read_service(tag, "svc", 8, time.monotonic() + 10)
    assert len(data) == 32  # still read, just not printed
    out = capsys.readouterr().out
    assert "ABCD" not in out
    assert "41 42" not in out


def test_read_service_respects_max_blocks(capsys):
    tag = FakeTag([b"\x00" * 16] * 10)
    data = main.read_service(tag, "svc", 3, time.monotonic() + 10)
    assert len(data) == 48
    assert "最大3ブロック" in capsys.readouterr().out


def test_read_service_stops_at_deadline():
    tag = FakeTag([b"\x00" * 16] * 10)
    assert main.read_service(tag, "svc", 5, time.monotonic() - 1) == b""


def test_mask():
    data = bytes.fromhex("0123456789ABCDEF")
    assert main.mask(data, reveal=False) == "*" * 16 + "  (8バイト)"
    assert main.mask(data, reveal=False, keep=2).startswith("0123" + "*" * 12)
    assert main.mask(data, reveal=True) == "0123456789ABCDEF"


class FakeRecord:
    type = "urn:nfc:wkt:U"

    def __str__(self):
        return "Resource 'https://example.com/secret'"


class FakeNdef:
    length = 16
    records = (FakeRecord(),)


class FakeType2:
    type = "Type2Tag"
    product = "NXP NTAG215"
    identifier = bytes.fromhex("04A1B2C3D4E5F6")
    ndef = FakeNdef()

    def __str__(self):
        return "Type2Tag ID=04A1B2C3D4E5F6"


def test_inspect_card_masks_by_default(capsys):
    assert main.inspect_card(FakeType2(), 4) is False
    out = capsys.readouterr().out
    assert "A1B2C3D4E5F6" not in out
    assert "secret" not in out
    assert "urn:nfc:wkt:U" in out
    assert "NXP NTAG215" in out


def test_inspect_card_reveal_shows_everything(capsys):
    main.inspect_card(FakeType2(), 4, reveal=True)
    out = capsys.readouterr().out
    assert "04A1B2C3D4E5F6" in out
    assert "secret" in out


class FakeFelica(FakeTag):
    type = "Type3Tag"
    identifier = bytes.fromhex("0123456789ABCDEF")
    pmm = bytes.fromhex("FEDCBA9876543210")
    ndef = None
    sys = 0

    def __init__(self):
        super().__init__([b"ABCD" + b"\x00" * 12])
        self.entries = [(0x0000, 0x00FF), (0x0409,), (0x040A,)]

    def request_system_code(self):
        return [0x1234, 0x5678]

    def polling(self, system):
        return self.identifier, self.pmm

    def search_service_code(self, index):
        return self.entries[index] if index < len(self.entries) else None


def test_felica_summary_has_no_codes_or_contents(capsys):
    main.inspect_card(FakeFelica(), 4)
    out = capsys.readouterr().out
    assert "6789ABCDEF" not in out
    assert "76543210" not in out
    assert "1234" not in out and "5678" not in out
    assert "ABCD" not in out
    assert "システム数: 2" in out
    assert "ASCII文字列候補" in out


def test_felica_reveal_shows_codes_and_contents(capsys):
    main.inspect_card(FakeFelica(), 4, reveal=True)
    out = capsys.readouterr().out
    assert "1234" in out
    assert "'ABCD'" in out
