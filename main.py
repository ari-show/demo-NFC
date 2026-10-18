"""Read one NFC card without writing or attempting authentication.

Identifiers, service codes and card contents are masked unless --reveal is given.
"""

import argparse
import re
import time

import nfc
from nfc.tag.tt3 import BlockCode, ServiceCode

# Service attributes that permit Read Without Encryption.
UNPROTECTED_ATTRIBUTES = {0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x15, 0x17}
MAX_SERVICE_ENTRIES = 256
INSPECTION_SECONDS = 30


def safe(value):
    """Neutralize control characters (ANSI escapes, bidi marks, ...) from card data."""
    return "".join(ch if ch.isprintable() else "." for ch in str(value))


def mask(data, reveal, keep=0):
    """Hide an identifier unless reveal is set; keep leading bytes that are not unique."""
    text = data.hex().upper()
    if reveal:
        return text
    return text[: keep * 2] + "*" * (len(text) - keep * 2) + f"  ({len(data)}バイト)"


def ascii_candidates(data):
    return list(re.finditer(rb"[\x20-\x7e]{4,}", data))


def read_service(tag, service, max_blocks, deadline, reveal=False):
    """Join bounded blocks before extracting strings across block boundaries.

    Block contents are printed only when reveal is set.
    """
    data = bytearray()
    for block in range(max_blocks):
        if time.monotonic() >= deadline:
            print("    調査時間の上限に達したため、ここで停止します。")
            break
        try:
            raw = bytes(tag.read_without_encryption([service], [BlockCode(block)]))
        except nfc.tag.TagCommandError as exc:
            if reveal:
                print(
                    f"    ブロック{block}で読み取り終了"
                    f"（範囲外・拒否・通信エラー等）: {safe(exc)}"
                )
            break
        data.extend(raw)
        if reveal:
            ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
            print(f"    [{block:04d}] {raw.hex(' ').upper()} | {ascii_text}")
    else:
        print(f"    最大{max_blocks}ブロックまで読みました。後続は未確認です。")

    if reveal:
        for match in ascii_candidates(data):
            print(
                f"    ASCII候補（バイト位置{match.start()}）: "
                f"{match.group().decode('ascii')!r}"
            )
    return bytes(data)


def inspect_felica(tag, max_blocks, reveal=False):
    """Enumerate systems/services and read only services that need no key.

    Without reveal, only aggregate counts are printed (no codes, no contents).
    """
    deadline = time.monotonic() + INSPECTION_SECONDS
    try:
        systems = tag.request_system_code()
    except nfc.tag.TagCommandError as exc:
        print(f"システム一覧を取得できませんでした: {safe(exc)}")
        return

    stats = {"areas": 0, "services": 0, "readable": 0, "blocks": 0, "strings": 0}
    if reveal:
        print("システムコード:", ", ".join(f"{code:04X}" for code in systems))
    for system in systems:
        if time.monotonic() >= deadline:
            print("FeliCa調査の時間上限に達しました。残りは未確認です。")
            break
        if reveal:
            print(f"\nシステム {system:04X}")
        try:
            # nfcpy's dump implementation also selects each logical system
            # and updates its potentially distinct IDm and PMm this way.
            tag.idm, tag.pmm = tag.polling(system)
            tag.sys = system
            for index in range(MAX_SERVICE_ENTRIES):
                if time.monotonic() >= deadline:
                    print("FeliCa調査の時間上限に達しました。残りは未確認です。")
                    break
                entry = tag.search_service_code(index)
                if entry is None:
                    break
                if len(entry) == 2:
                    stats["areas"] += 1
                    if reveal:
                        print(f"  エリア {entry[0]:04X}〜{entry[1]:04X}")
                    continue
                code = entry[0]
                service = ServiceCode(code >> 6, code & 0x3F)
                stats["services"] += 1
                if reveal:
                    print(f"  {safe(service)}")
                if service.attribute not in UNPROTECTED_ATTRIBUTES:
                    if reveal:
                        print(
                            "    認証が必要、または未対応の属性のため読み取り対象外です。"
                        )
                    continue
                stats["readable"] += 1
                data = read_service(tag, service, max_blocks, deadline, reveal)
                stats["blocks"] += len(data) // 16
                stats["strings"] += len(ascii_candidates(data))
            else:
                print(
                    f"  エリア・サービスの探索上限{MAX_SERVICE_ENTRIES}件に達しました。"
                )
        except nfc.tag.TagCommandError as exc:
            print(f"  このシステムの調査を中断しました: {safe(exc)}")

    if not reveal:
        print(f"システム数: {len(systems)}（コードは非表示）")
        print(f"エリア数: {stats['areas']}、サービス数: {stats['services']}")
        print(f"認証不要のサービス数: {stats['readable']}")
        print(f"読み取れたブロック数: {stats['blocks']}")
        print(f"ASCII文字列候補: {stats['strings']}件（内容は非表示）")


def inspect_card(tag, max_blocks, reveal=False):
    print("\nカードを検出しました。読み取り終了まで動かさないでください。", flush=True)
    print("カード種類:", safe(tag.type))
    if reveal:
        print("詳細:", safe(tag))
    elif getattr(tag, "product", None):
        print("製品名:", safe(tag.product))
    label = "IDm" if tag.type == "Type3Tag" else "UID"
    # The first two IDm bytes are a manufacturer code and do not identify a card.
    keep = 2 if tag.type == "Type3Tag" else 0
    print(f"{label}:", mask(tag.identifier, reveal, keep))
    if hasattr(tag, "pmm"):
        print("PMm:", mask(tag.pmm, reveal))

    try:
        ndef = tag.ndef
        if ndef is None:
            print("NDEF: 取得できませんでした（他形式のデータがある場合もあります）。")
        else:
            print(f"NDEF: {ndef.length}バイト")
            for index, record in enumerate(ndef.records, 1):
                shown = (
                    safe(record) if reveal else f"{safe(record.type)}（内容は非表示）"
                )
                print(f"  レコード{index}: {shown}")
    except (nfc.tag.TagCommandError, ValueError) as exc:
        print(f"NDEFの読み取り・解析に失敗しました: {safe(exc)}")

    if all(
        callable(getattr(tag, name, None))
        for name in (
            "request_system_code",
            "search_service_code",
            "read_without_encryption",
        )
    ):
        inspect_felica(tag, max_blocks, reveal)
    elif tag.type == "Type3Tag":
        print("このカードではFeliCaのシステム・サービス探索を利用できません。")
    print("\n読み取り処理を終了しました。書き込みは行っていません。", flush=True)
    return False  # Finish after one card; do not wait for removal.


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("1以上の整数を指定してください。")
    return number


def main():
    parser = argparse.ArgumentParser(
        description="NFCカードを1枚、読み取り専用で調査します。"
    )
    parser.add_argument("--device", default="usb:054c:06c1", help="nfcpyのデバイス指定")
    parser.add_argument(
        "--timeout", type=positive_int, default=180, help="カード待機秒数（既定: 180）"
    )
    parser.add_argument(
        "--max-blocks",
        type=positive_int,
        default=32,
        help="1サービスの最大読み取りブロック数（既定: 32）",
    )
    parser.add_argument(
        "--reveal",
        action="store_true",
        help="ID・コード・カード内のデータを伏せずに表示する（自分のカードの確認用）",
    )
    args = parser.parse_args()
    if args.max_blocks > 65536:
        parser.error("--max-blocksは65536以下を指定してください。")

    try:
        with nfc.ContactlessFrontend(args.device) as reader:
            print("リーダー:", safe(reader), flush=True)
            print(
                f"カードをかざしてください（最大{args.timeout}秒待機、Ctrl+Cで終了）。",
                flush=True,
            )
            deadline = time.monotonic() + args.timeout
            tag = reader.connect(
                rdwr={
                    "on-connect": lambda card: inspect_card(
                        card, args.max_blocks, args.reveal
                    )
                },
                terminate=lambda: time.monotonic() >= deadline,
            )
            if not tag:
                print("カードを取得できず終了しました（時間切れ・中断・接続エラー）。")
                return 1
    except KeyboardInterrupt:
        print("\n読み取りを中断しました。")
        return 130
    except (OSError, nfc.tag.TagCommandError) as exc:
        print(f"読み取りエラー: {safe(exc)}")
        print(
            "USB接続、libusbの導入、USBアクセス権限、他アプリの使用状況を確認してください。"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
