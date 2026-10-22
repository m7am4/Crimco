"""Shared helpers: file type detection, hashing, strings extraction, flag search."""

import hashlib
import re

# Default pattern matches common CTF flag formats like flag{...}, CTF{...}, picoCTF{...}
DEFAULT_FLAG_PATTERN = r"[A-Za-z0-9_]{0,20}\{[^{}\s]{1,200}\}"

# Known "magic bytes" at the start of files
MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP archive (also docx/xlsx/jar/apk)"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF executable (Linux)"),
    (b"MZ", "PE executable (Windows)"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xd4\xc3\xb2\xa1", "PCAP network capture"),
    (b"\xa1\xb2\xc3\xd4", "PCAP network capture"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG network capture"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"RIFF", "RIFF container (WAV/AVI/WEBP)"),
    (b"ID3", "MP3 audio"),
    (b"BM", "BMP image"),
]


def detect_file_type(data):
    """Guess the file type from its first bytes."""
    for signature, name in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return name
    if data and all(32 <= b < 127 or b in (9, 10, 13) for b in data[:512]):
        return "Text file"
    return "Unknown (raw data)"


def file_hashes(data):
    """Return MD5, SHA1 and SHA256 of the data."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def extract_strings(data, min_length=4):
    """Return printable ASCII strings, like the Linux `strings` command."""
    pattern = rb"[\x20-\x7e]{%d,}" % min_length
    return [s.decode("ascii") for s in re.findall(pattern, data)]


def find_flags(text, pattern=DEFAULT_FLAG_PATTERN):
    """Return unique flag-looking matches in the text, in order found."""
    seen = []
    for match in re.findall(pattern, text):
        if match not in seen:
            seen.append(match)
    return seen
