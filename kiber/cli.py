"""Command-line interface for Kiber.

Usage examples:
    python -m kiber analyze challenge.png
    python -m kiber strings challenge.bin -n 6
    python -m kiber flags notes.txt --pattern "HTB\\{.*?\\}"
    python -m kiber history
    python -m kiber history --search png
"""

import argparse
import os
import sys

from kiber import history, utils


def read_file(path):
    """Read a file as bytes, or exit with a clear error message."""
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read()


# ---------- commands ----------

def cmd_analyze(args):
    data = read_file(args.file)
    file_type = utils.detect_file_type(data)
    hashes = utils.file_hashes(data)
    strings = utils.extract_strings(data, args.min_length)
    flags = utils.find_flags("\n".join(strings), args.pattern)

    print(f"[*] File:   {args.file}")
    print(f"[*] Size:   {len(data)} bytes")
    print(f"[*] Type:   {file_type}")
    for name, value in hashes.items():
        print(f"[*] {name.upper():<6}  {value}")
    print(f"[*] Strings found: {len(strings)}")

    if flags:
        print("\n[+] Possible flags:")
        for flag in flags:
            print(f"    {flag}")
    else:
        print("\n[-] No flags found in strings. Try: kiber strings <file> to look manually.")

    history.save("analyze", args.file, flags, {"type": file_type, **hashes})


def cmd_strings(args):
    data = read_file(args.file)
    strings = utils.extract_strings(data, args.min_length)
    for s in strings:
        print(s)
    history.save("strings", args.file, details={"count": len(strings)})


def cmd_flags(args):
    data = read_file(args.file)
    text = "\n".join(utils.extract_strings(data, 4))
    flags = utils.find_flags(text, args.pattern)
    if flags:
        for flag in flags:
            print(f"[+] {flag}")
    else:
        print("[-] No flags found.")
    history.save("flags", args.file, flags)


def cmd_history(args):
    if args.clear:
        history.clear()
        print("[*] History cleared.")
        return

    entries = history.load(args.limit, args.search)
    if not entries:
        print("[-] No history yet.")
        return

    for e in entries:
        flags = ", ".join(e["flags"]) if e["flags"] else "-"
        print(f"#{e['id']:<4} {e['time']}  {e['command']:<8} {e['target']}  flags: {flags}")


# ---------- argument parsing ----------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="kiber",
        description="Kiber - a CTF helper for forensics, reversing, crypto and stego.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("analyze", help="Detect file type, hashes, strings and flags")
    p.add_argument("file", help="Path to the challenge file")
    p.add_argument("-n", "--min-length", type=int, default=4, help="Minimum string length (default 4)")
    p.add_argument("--pattern", default=utils.DEFAULT_FLAG_PATTERN, help="Regex for the flag format")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("strings", help="Print readable strings from a file")
    p.add_argument("file")
    p.add_argument("-n", "--min-length", type=int, default=4)
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("flags", help="Search a file for flags")
    p.add_argument("file")
    p.add_argument("--pattern", default=utils.DEFAULT_FLAG_PATTERN, help="Regex for the flag format")
    p.set_defaults(func=cmd_flags)

    p = sub.add_parser("history", help="Show past actions")
    p.add_argument("--limit", type=int, default=20, help="How many entries to show")
    p.add_argument("--search", help="Only show entries containing this word")
    p.add_argument("--clear", action="store_true", help="Delete all history")
    p.set_defaults(func=cmd_history)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
