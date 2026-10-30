#!/usr/bin/env python3
"""Read-only diagnosis of retained clean-build image identity differences."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


ROOT = Path(__file__).resolve().parent.parent


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def sections(blob):
    offset, = struct.unpack_from("<Q", blob, 40)
    size, count, strings_index = struct.unpack_from("<HHH", blob, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", blob, offset + n * size)
               for n in range(count)]
    header = headers[strings_index]
    strings = blob[header[4]:header[4] + header[5]]
    result = {}
    for header in headers:
        end = strings.index(0, header[0])
        name = strings[header[0]:end].decode("ascii")
        result[name] = {
            "type": header[1], "address": header[3], "offset": header[4],
            "bytes": header[5], "sha256": digest(blob[header[4]:header[4] + header[5]])
            if header[1] != 8 else None,
        }
    return result


def file_symbols(blob, section_map):
    symbols, strings = section_map[".symtab"], section_map[".strtab"]
    table = blob[strings["offset"]:strings["offset"] + strings["bytes"]]
    result = []
    for offset in range(symbols["offset"], symbols["offset"] + symbols["bytes"], 24):
        name, info, _, _, _, _ = struct.unpack_from("<IBBHQQ", blob, offset)
        if info & 15 == 4:
            result.append(table[name:table.index(0, name)].decode("ascii"))
    return result


def cpio_entries(blob):
    offset, result = 0, []
    while True:
        if blob[offset:offset + 6] != b"070701":
            raise AssertionError("Invalid retained newc archive")
        fields = [int(blob[offset + 6 + n * 8:offset + 14 + n * 8], 16)
                  for n in range(13)]
        offset += 110
        name = blob[offset:offset + fields[11] - 1].decode("ascii")
        offset = (offset + fields[11] + 3) & ~3
        payload = blob[offset:offset + fields[6]]
        result.append({"name": name, "mtime": fields[5], "bytes": fields[6],
                       "payload_sha256": digest(payload)})
        offset = (offset + fields[6] + 3) & ~3
        if name == "TRAILER!!!":
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original", required=True)
    parser.add_argument("--clean", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    original_path, clean_path = ROOT / args.original, ROOT / args.clean
    original, clean = [json.loads(path.read_text()) for path in (original_path, clean_path)]
    clean_root = clean_path.parents[2]
    records = []
    for name in sorted(original["images"]):
        left, right = original["images"][name], clean["images"][name]
        old_blob = (ROOT / left["path"]).read_bytes()
        new_blob = (clean_root / right["path"]).read_bytes()
        if digest(old_blob) != left["sha256"] or digest(new_blob) != right["sha256"]:
            raise AssertionError(f"Retained image changed: {name}")
        record = {"image": name, "identical": old_blob == new_blob,
                  "original_bytes": len(old_blob), "clean_bytes": len(new_blob)}
        if old_blob != new_blob:
            differences = [n for n, (a, b) in enumerate(zip(old_blob, new_blob)) if a != b]
            record["different_bytes_in_common_extent"] = len(differences)
            record["first_differences"] = [{
                "offset": n, "original_hex": old_blob[max(0, n - 8):n + 24].hex(),
                "clean_hex": new_blob[max(0, n - 8):n + 24].hex(),
            } for n in differences[:8]]
            if old_blob.startswith(b"\x7fELF"):
                old_sections, new_sections = sections(old_blob), sections(new_blob)
                record["different_sections"] = {
                    key: {"original": old_sections.get(key), "clean": new_sections.get(key)}
                    for key in old_sections.keys() | new_sections.keys()
                    if old_sections.get(key) != new_sections.get(key)
                }
                if name in ("init", "fw_jump.elf"):
                    record["file_symbols"] = {
                        "original": file_symbols(old_blob, old_sections),
                        "clean": file_symbols(new_blob, new_sections),
                    }
            if name == "initramfs.cpio":
                record["cpio_entries"] = {"original": cpio_entries(old_blob),
                                          "clean": cpio_entries(new_blob)}
            if name in ("Image", "vmlinux"):
                record["private_root_occurrences"] = {
                    "original": old_blob.count(str(ROOT).encode()),
                    "clean": new_blob.count(str(clean_root).encode()),
                }
                record["path_string_samples"] = {}
                for label, blob in (("original", old_blob), ("clean", new_blob)):
                    record["path_string_samples"][label] = [
                        string.decode("ascii", "backslashreplace")
                        for string in blob.split(b"\0")
                        if b"/linux-6.6.1/" in string and all(32 <= c < 127 for c in string)
                    ][:8]
        records.append(record)
    summary = {
        "original": args.original, "clean": args.clean,
        "software_sources_identical": original["sources"] == clean["sources"],
        "tool_versions_identical": original["tools"] == clean["tools"],
        "platform_identical": original["platform"] == clean["platform"],
        "frozen_source_date_epoch": original["platform"]["source_date_epoch"],
        "images": records,
    }
    (out / "comparison.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
