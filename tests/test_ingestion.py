import io
import stat
import zipfile

import pytest
from conftest import archive
from hypothesis import given
from hypothesis import strategies as st

from sentinel.ingestion import IngestionError, ingest_zip, safe_path, verify_snapshot


@pytest.mark.parametrize(
    "name",
    [
        "../evil.sol",
        "/evil.sol",
        "a/../../evil.sol",
        "a\\evil.sol",
        "C:evil.sol",
        ".git/config",
        "a/./b.sol",
        "evil\x00.sol",
    ],
)
def test_unsafe_paths(name, tmp_path):
    with pytest.raises(IngestionError):
        ingest_zip(archive({name: "pragma solidity ^0.8.20;"}), tmp_path)


@given(
    st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")), min_size=1, max_size=40
    )
)
def test_path_traversal_property(part):
    with pytest.raises(IngestionError):
        safe_path(f"{part}/../bad.sol")


def test_symlink(tmp_path):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as zipped:
        entry = zipfile.ZipInfo("escape.sol")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        zipped.writestr(entry, "/etc/passwd")
    with pytest.raises(IngestionError, match="Links"):
        ingest_zip(data.getvalue(), tmp_path)


def test_snapshot_is_deterministic_and_tamper_checked(tmp_path):
    content = {"B.sol": "pragma solidity ^0.8.20;", "A.sol": "contract A {}"}
    first, snapshot = ingest_zip(archive(content), tmp_path)
    second, _ = ingest_zip(archive(dict(reversed(list(content.items())))), tmp_path)
    assert first.revision == second.revision
    assert first.git_commit is None
    verify_snapshot(first, snapshot)
    target = snapshot / "A.sol"
    target.chmod(0o644)
    target.write_text("modified")
    with pytest.raises(IngestionError, match="hash"):
        verify_snapshot(first, snapshot)


@pytest.mark.parametrize(
    "entries", [{"x.ts": "alert(1)"}, {"readme.md": "hi"}, {"A.sol": "a", "a.sol": "b"}]
)
def test_reject_unsupported_empty_and_collision(entries, tmp_path):
    with pytest.raises(IngestionError):
        ingest_zip(archive(entries), tmp_path)


def test_expansion_limit(tmp_path):
    with pytest.raises(IngestionError, match="size"):
        ingest_zip(archive({"large.sol": "a" * (1024 * 1024 + 1)}), tmp_path)


def test_file_directory_conflict_is_rejected_before_writing(tmp_path):
    with pytest.raises(IngestionError, match="conflicts"):
        ingest_zip(archive({"A.sol": "contract A {}", "A.sol/B.sol": "contract B {}"}), tmp_path)
    assert list(tmp_path.iterdir()) == []
