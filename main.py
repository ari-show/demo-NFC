"""Read one NFC card without writing or attempting authentication."""

import argparse
import re
import time

import nfc
from nfc.tag.tt3 import BlockCode, ServiceCode


# Service attributes that permit Read Without Encryption.
UNPROTECTED_ATTRIBUTES = {0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x15, 0x17}
MAX_SERVICE_ENTRIES = 256
INSPECTION_SECONDS = 30


def read_service(tag, service, max_blocks, deadline):
    """Join bounded blocks before extracting strings across block boundaries."""
    data = bytearray()
    for block in range(max_blocks):
        if time.monotonic() >= deadline:
            print("    調査時間の上限に達したため、ここで停止します。")
            break
        try:
            raw = bytes(tag.read_without_encryption([service], [BlockCode(block)]))
        except nfc.tag.TagCommandError as exc:
            print(f"    ブロック{block}で読み取り終了（範囲外・拒否・通信エラー等）: {exc}")
            break
        data.extend(raw)
        ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        print(f"    [{block:04d}] {raw.hex(' ').upper()} | {ascii_text}")
    else:
        print(f"    最大{max_blocks}ブロックまで表示しました。後続は未確認です。")

    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        print(f"    ASCII候補（バイト位置{match.start()}）: {match.group().decode('ascii')!r}")
    return bytes(data)


def inspect_felica(tag, max_blocks):
    """Enumerate systems/services and read only services that need no key."""
    deadline = time.monotonic() + INSPECTION_SECONDS
    try:
        systems = tag.request_system_code()
    except nfc.tag.TagCommandError as exc:
        print(f"システム一覧を取得できませんでした: {exc}")
        return

    print("システムコード:", ", ".join(f"{code:04X}" for code in systems))
    for system in systems:
        if time.monotonic() >= deadline:
            print("FeliCa調査の時間上限に達しました。残りは未確認です。")
            return
        print(f"\nシステム {system:04X}")
        try:
            # nfcpy's dump implementation also selects each logical system
            # and updates its potentially distinct IDm and PMm this way.
            tag.idm, tag.pmm = tag.polling(system)
            tag.sys = system
            for index in range(MAX_SERVICE_ENTRIES):
                if time.monotonic() >= deadline:
                    print("FeliCa調査の時間上限に達しました。残りは未確認です。")
                    return
                entry = tag.search_service_code(index)
                if entry is None:
                    break
                if len(entry) == 2:
                    print(f"  エリア {entry[0]:04X}〜{entry[1]:04X}")
                    continue
                code = entry[0]
                service = ServiceCode(code >> 6, code & 0x3F)
                print(f"  {service}")
                if service.attribute not in UNPROTECTED_ATTRIBUTES:
                    print("    認証が必要、または未対応の属性のため読み取り対象外です。")
                    continue
                read_service(tag, service, max_blocks, deadline)
            else:
                print(f"  エリア・サービスの探索上限{MAX_SERVICE_ENTRIES}件に達しました。")
        except nfc.tag.TagCommandError as exc:
            print(f"  このシステムの調査を中断しました: {exc}")


def inspect_card(tag, max_blocks):
    print("\nカードを検出しました。読み取り終了まで動かさないでください。", flush=True)
    print("カード種類:", tag.type)
    print("詳細:", tag)
    label = "IDm" if tag.type == "Type3Tag" else "UID"
    print(f"{label}:", tag.identifier.hex().upper())
    if hasattr(tag, "pmm"):
        print("PMm:", tag.pmm.hex().upper())

    try:
        ndef = tag.ndef
        if ndef is None:
            print("NDEF: 取得できませんでした（他形式のデータがある場合もあります）。")
        else:
            print(f"NDEF: {ndef.length}バイト")
            for index, record in enumerate(ndef.records, 1):
                print(f"  レコード{index}: {record}")
    except (nfc.tag.TagCommandError, ValueError) as exc:
        print(f"NDEFの読み取り・解析に失敗しました: {exc}")

    if all(callable(getattr(tag, name, None)) for name in (
        "request_system_code", "search_service_code", "read_without_encryption"
    )):
        inspect_felica(tag, max_blocks)
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
    parser = argparse.ArgumentParser(description="NFCカードを1枚、読み取り専用で調査します。")
    parser.add_argument("--device", default="usb:054c:06c1", help="nfcpyのデバイス指定")
    parser.add_argument("--timeout", type=positive_int, default=180, help="カード待機秒数（既定: 180）")
    parser.add_argument("--max-blocks", type=positive_int, default=32,
                        help="1サービスの最大読み取りブロック数（既定: 32）")
    args = parser.parse_args()
    if args.max_blocks > 65536:
        parser.error("--max-blocksは65536以下を指定してください。")

    try:
        with nfc.ContactlessFrontend(args.device) as reader:
            print("リーダー:", reader, flush=True)
            print(f"カードをかざしてください（最大{args.timeout}秒待機、Ctrl+Cで終了）。", flush=True)
            deadline = time.monotonic() + args.timeout
            tag = reader.connect(
                rdwr={"on-connect": lambda card: inspect_card(card, args.max_blocks)},
                terminate=lambda: time.monotonic() >= deadline,
            )
            if not tag:
                print("カードを取得できず終了しました（時間切れ・中断・接続エラー）。")
                return 1
    except KeyboardInterrupt:
        print("\n読み取りを中断しました。")
        return 130
    except (OSError, nfc.tag.TagCommandError) as exc:
        print(f"読み取りエラー: {exc}")
        print("USB接続、libusbの導入、USBアクセス権限、他アプリの使用状況を確認してください。")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

