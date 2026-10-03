"""Build an offline NetScaler firmware fingerprint corpus from local archives.

No archive member is extracted to disk or executed. Fingerprints identify
candidate builds; a collision is preserved as multiple candidates.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


_GUI_NAME = re.compile(r"^ns-(\d+(?:\.\d+)+-\d+\.\d+)-gui\.tar$", re.IGNORECASE)
_INDEX_TOKEN = re.compile(rb"\?v=([0-9a-f]{32})(?![0-9a-z_])", re.IGNORECASE)
_INDEX_PATH = ("vpn", "index.html")
_RDX_PATH = ("vpn", "js", "rdx", "core", "lang", "rdx_en.json.gz")
_MAX_INDEX_BYTES = 2 * 1024 * 1024


def _safe_parts(name):
    """Return normalized member path parts, or an empty tuple if unsafe."""
    if not name or name.startswith("/") or "\\" in name:
        return ()
    parts = PurePosixPath(name).parts
    if not parts or ".." in parts or any(":" in part for part in parts):
        return ()
    return parts


def _package_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_fingerprints(path):
    package_sha256 = _package_sha256(path)
    found_gui = False
    with tarfile.open(path, mode="r:*") as package:
        for gui_member in package:
            parts = _safe_parts(gui_member.name)
            if not parts or not gui_member.isfile():
                continue
            match = _GUI_NAME.fullmatch(parts[-1])
            if not match:
                continue
            found_gui = True
            candidate = {
                "build": match.group(1),
                "package_sha256": package_sha256,
                "package_name": path.name,
                "gui_member": gui_member.name,
            }
            with package.extractfile(gui_member) as gui_stream:
                with tarfile.open(fileobj=gui_stream, mode="r|*") as gui:
                    for member in gui:
                        asset_parts = _safe_parts(member.name)
                        if not asset_parts or not member.isfile():
                            continue
                        if asset_parts[-len(_INDEX_PATH):] == _INDEX_PATH:
                            if member.size > _MAX_INDEX_BYTES:
                                continue
                            with gui.extractfile(member) as index_stream:
                                data = index_stream.read(_MAX_INDEX_BYTES + 1)
                            if len(data) <= _MAX_INDEX_BYTES:
                                for token in set(_INDEX_TOKEN.findall(data)):
                                    yield "vpn_index_v", token.decode("ascii").lower(), candidate
                        elif asset_parts[-len(_RDX_PATH):] == _RDX_PATH:
                            with gui.extractfile(member) as gzip_stream:
                                header = gzip_stream.read(8)
                            if len(header) == 8 and header[:3] == b"\x1f\x8b\x08":
                                mtime = int.from_bytes(header[4:8], "little")
                                if mtime:
                                    yield "rdx_en_gzip_mtime", str(mtime), candidate
    if not found_gui:
        raise ValueError(f"{path.name}: no NetScaler GUI archive found")


def build_firmware_corpus(package_paths):
    """Return JSON-ready fingerprint mappings for local firmware packages.

    Each fingerprint maps to every distinct build and archive provenance that
    contains it. Zero GZIP MTIME is omitted because it is a stripped timestamp.
    """
    collected = {"vpn_index_v": {}, "rdx_en_gzip_mtime": {}}
    for package_path in package_paths:
        path = Path(package_path)
        for kind, fingerprint, candidate in _archive_fingerprints(path):
            key = (candidate["build"], candidate["package_sha256"],
                   candidate["package_name"], candidate["gui_member"])
            collected[kind].setdefault(fingerprint, {})[key] = candidate
    return {
        "schema_version": 1,
        "fingerprints": {
            kind: {fingerprint: [entries[key] for key in sorted(entries)]
                   for fingerprint, entries in sorted(mapping.items())}
            for kind, mapping in collected.items()
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+", help="local Citrix firmware .tgz packages")
    parser.add_argument("-o", "--output", required=True, help="output JSON file")
    args = parser.parse_args(argv)
    output = Path(args.output)
    for package_name in args.packages:
        package = Path(package_name)
        if (output.resolve() == package.resolve() or
                (output.exists() and output.samefile(package))):
            parser.error("output path must differ from every input package")
    corpus = build_firmware_corpus(args.packages)
    output.write_text(json.dumps(corpus, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
