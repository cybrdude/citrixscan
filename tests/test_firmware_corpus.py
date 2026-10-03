"""Corpus creation from operator-supplied firmware archives."""

import gzip
import hashlib
import io
import json
import subprocess
import sys
import tarfile

from firmware_corpus import build_firmware_corpus
import pytest


def tar_bytes(members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in members:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def package(tmp_path, build, token, mtime, name="firmware.tgz"):
    gui = tar_bytes([
        ("./vpn/index.html", f'<script src="app.js?v={token}"></script>'.encode()),
        ("vpn/js/rdx/core/lang/rdx_en.json.gz", gzip.compress(b"{}", mtime=mtime)),
    ])
    path = tmp_path / name
    with tarfile.open(path, mode="w:gz") as outer:
        entry = tarfile.TarInfo(f"firmware/ns-{build}-gui.tar")
        entry.size = len(gui)
        outer.addfile(entry, io.BytesIO(gui))
    return path


def test_extracts_stock_gui_token_and_gzip_mtime_with_package_provenance(tmp_path):
    token = "0123456789abcdef0123456789abcdef"
    archive = package(tmp_path, "14.1-65.11", token, 1735689600)

    corpus = build_firmware_corpus([archive])

    expected_candidate = {
        "build": "14.1-65.11",
        "package_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "package_name": "firmware.tgz",
        "gui_member": "firmware/ns-14.1-65.11-gui.tar",
    }
    assert corpus["fingerprints"]["vpn_index_v"][token] == [expected_candidate]
    assert corpus["fingerprints"]["rdx_en_gzip_mtime"]["1735689600"] == [expected_candidate]


def test_does_not_truncate_a_longer_version_query_value(tmp_path):
    token = "0123456789abcdef0123456789abcdef"
    archive = package(tmp_path, "14.1-65.11", token + "z", 1735689600)

    corpus = build_firmware_corpus([archive])

    assert corpus["fingerprints"]["vpn_index_v"] == {}


def test_shared_fingerprints_retain_both_builds(tmp_path):
    token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    first = package(tmp_path, "14.1-65.11", token, 1735689600, "first.tgz")
    second = package(tmp_path, "14.1-73.37", token, 1735689600, "second.tgz")

    corpus = build_firmware_corpus([second, first])

    for kind, value in [("vpn_index_v", token),
                        ("rdx_en_gzip_mtime", "1735689600")]:
        candidates = corpus["fingerprints"][kind][value]
        assert [candidate["build"] for candidate in candidates] == [
            "14.1-65.11", "14.1-73.37",
        ]
        assert {candidate["package_sha256"] for candidate in candidates} == {
            hashlib.sha256(first.read_bytes()).hexdigest(),
            hashlib.sha256(second.read_bytes()).hexdigest(),
        }


def test_ignores_unsafe_and_symlinked_gui_members(tmp_path):
    token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    gui = tar_bytes([("vpn/index.html", f"?v={token}".encode())])
    archive = tmp_path / "unsafe.tgz"
    with tarfile.open(archive, mode="w:gz") as outer:
        traversal = tarfile.TarInfo("../ns-14.1-65.11-gui.tar")
        traversal.size = len(gui)
        outer.addfile(traversal, io.BytesIO(gui))
        link = tarfile.TarInfo("ns-14.1-65.11-gui.tar")
        link.type = tarfile.SYMTYPE
        link.linkname = "../ns-14.1-65.11-gui.tar"
        outer.addfile(link)
        safe_gui = tar_bytes([("unrelated.txt", b"nothing to fingerprint")])
        safe = tarfile.TarInfo("ns-14.1-73.37-gui.tar")
        safe.size = len(safe_gui)
        outer.addfile(safe, io.BytesIO(safe_gui))

    corpus = build_firmware_corpus([archive])

    assert corpus["fingerprints"]["vpn_index_v"] == {}


def test_cli_writes_json_with_candidates(tmp_path):
    token = "cccccccccccccccccccccccccccccccc"
    archive = package(tmp_path, "14.1-65.11", token, 1735689600)
    output = tmp_path / "corpus.json"

    proc = subprocess.run(
        [sys.executable, "-m", "firmware_corpus", "-o", str(output), str(archive)],
        capture_output=True, text=True, check=False,
    )

    assert proc.returncode == 0, proc.stderr
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["fingerprints"]["vpn_index_v"][token][0]["build"] == "14.1-65.11"


def test_rejects_package_without_a_matching_gui_archive(tmp_path):
    archive = tmp_path / "unrelated.tgz"
    with tarfile.open(archive, mode="w:gz") as outer:
        entry = tarfile.TarInfo("readme.txt")
        entry.size = 5
        outer.addfile(entry, io.BytesIO(b"hello"))

    with pytest.raises(ValueError, match="no NetScaler GUI archive"):
        build_firmware_corpus([archive])


def test_cli_never_overwrites_an_input_package(tmp_path):
    token = "dddddddddddddddddddddddddddddddd"
    archive = package(tmp_path, "14.1-65.11", token, 1735689600)
    original_hash = hashlib.sha256(archive.read_bytes()).hexdigest()

    proc = subprocess.run(
        [sys.executable, "-m", "firmware_corpus", "-o", str(archive), str(archive)],
        capture_output=True, text=True, check=False,
    )

    assert proc.returncode != 0
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == original_hash
