#!/usr/bin/env python3
"""Write a zip that Windows Explorer can open.

The Windows release job uses Git Bash. Its tar is GNU tar, which has no zip
writer: `tar -a -cf name.zip` still stores a GNU tar archive. Explorer then
reports that the compressed folder is invalid.

This writes a deflate zip with the CRC and sizes in each local header, so
general-purpose bit 3 stays clear. Explorer rejects archives that set that
bit. Entry names use '/', which is what the zip format requires. The updater
unpacks this file with Windows tar.
"""

import sys
import zipfile
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: windows-zip.py <source-dir> <destination.zip>", file=sys.stderr)
        raise SystemExit(2)
    source = Path(sys.argv[1]).resolve()
    dest = Path(sys.argv[2])
    if not source.is_dir():
        print(f"not a directory: {source}", file=sys.stderr)
        raise SystemExit(1)
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files:
        print(f"nothing to pack in {source}", file=sys.stderr)
        raise SystemExit(1)
    if dest.exists():
        dest.unlink()

    root = source.name
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            entry = f"{root}/{path.relative_to(source).as_posix()}"
            archive.write(path, entry)

    verify(dest, f"{root}/g-ssh.exe")


def verify(path: Path, exe_entry: str) -> None:
    data = path.read_bytes()
    if len(data) < 30 or data[:4] != b"PK\x03\x04":
        raise SystemExit(f"not a zip file: {path}")
    found = False
    offset = 0
    while offset + 30 <= len(data) and data[offset : offset + 4] == b"PK\x03\x04":
        flags = int.from_bytes(data[offset + 6 : offset + 8], "little")
        if flags & 0x08:
            raise SystemExit("zip uses a data descriptor, which Windows Explorer rejects")
        compressed = int.from_bytes(data[offset + 18 : offset + 22], "little")
        if compressed == 0xFFFFFFFF:
            raise SystemExit("unexpected zip64 local header")
        name_len = int.from_bytes(data[offset + 26 : offset + 28], "little")
        extra_len = int.from_bytes(data[offset + 28 : offset + 30], "little")
        name = data[offset + 30 : offset + 30 + name_len].decode("utf-8")
        if "\\" in name:
            raise SystemExit(f"zip entry uses a backslash: {name}")
        if name == exe_entry:
            found = True
        offset += 30 + name_len + extra_len + compressed
    if not found:
        raise SystemExit(f"zip is missing {exe_entry}")


if __name__ == "__main__":
    main()
