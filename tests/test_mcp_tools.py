"""
Funktionale Tests für alle MCP-Filesystem-Tools.
Verifiziert das korrekte Verhalten der MCP-Tool-Funktionen als Python-Funktionen.
"""

import base64
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lokales_dateisystem as fs

# ---------------------------------------------------------------------------
# read_file / write_file
# ---------------------------------------------------------------------------


class TestReadWriteFile:
    def test_write_and_read_roundtrip(self, tmp_path):
        path = str(tmp_path / "test.txt")
        result = fs.write_file(path, "hello world")
        assert result["success"] is True
        assert result["bytes_written"] == 11

        result = fs.read_file(path)
        assert result["success"] is True
        assert result["content"] == "hello world"
        assert result["lines"] == 1

    def test_write_append(self, tmp_path):
        path = str(tmp_path / "append.txt")
        fs.write_file(path, "line1\n")
        fs.write_file(path, "line2\n", append=True)
        result = fs.read_file(path)
        assert "line1" in result["content"]
        assert "line2" in result["content"]

    def test_write_creates_file(self, tmp_path):
        path = str(tmp_path / "new.txt")
        assert not os.path.exists(path)
        fs.write_file(path, "created")
        assert os.path.exists(path)

    def test_read_nonexistent_returns_error(self, tmp_path):
        result = fs.read_file(str(tmp_path / "nope.txt"))
        assert "error" in result

    def test_read_directory_returns_error(self, tmp_path):
        result = fs.read_file(str(tmp_path))
        assert "error" in result

    def test_write_invalid_encoding(self, tmp_path):
        path = str(tmp_path / "test.txt")
        result = fs.write_file(path, "hello", encoding="nonexistent-codec")
        assert "error" in result

    def test_multiline_file(self, tmp_path):
        path = str(tmp_path / "multi.txt")
        content = "line1\nline2\nline3\n"
        fs.write_file(path, content)
        result = fs.read_file(path)
        assert result["lines"] == 3


class TestReadFileBinary:
    def test_write_and_read_binary(self, tmp_path):
        path = str(tmp_path / "test.bin")
        data = bytes(range(256))
        encoded = base64.b64encode(data).decode()
        result = fs.write_file_binary(path, encoded)
        assert result["success"] is True

        result = fs.read_file_binary(path)
        assert result["success"] is True
        assert result["encoding"] == "base64"
        decoded = base64.b64decode(result["content"])
        assert decoded == data

    def test_invalid_base64_rejected(self, tmp_path):
        path = str(tmp_path / "test.bin")
        result = fs.write_file_binary(path, "not-valid-base64!!!")
        assert "error" in result


class TestGetFileLines:
    def test_read_range(self, tmp_path):
        path = str(tmp_path / "lines.txt")
        fs.write_file(path, "\n".join(f"line{i}" for i in range(10)))
        result = fs.get_file_lines(path, start=2, end=5)
        assert result["success"] is True
        assert result["returned_lines"] == 3
        assert "line2" in result["content"]

    def test_read_to_end(self, tmp_path):
        path = str(tmp_path / "lines.txt")
        fs.write_file(path, "a\nb\nc\n")
        result = fs.get_file_lines(path, start=1)
        assert "b" in result["content"]


# ---------------------------------------------------------------------------
# Verzeichnisoperationen
# ---------------------------------------------------------------------------


class TestListDirectory:
    def test_flat_listing(self, tmp_workdir):
        result = fs.list_directory(str(tmp_workdir))
        assert result["success"] is True
        names = {e["name"] for e in result["entries"]}
        assert "hello.txt" in names
        assert "subdir" in names

    def test_recursive_listing(self, tmp_workdir):
        result = fs.list_directory(str(tmp_workdir), recursive=True)
        assert result["success"] is True
        names = {e["name"] for e in result["entries"]}
        # relative paths - nested file must appear
        assert any("nested.txt" in n for n in names)

    def test_hidden_files_excluded_by_default(self, tmp_path):
        (tmp_path / ".hidden").write_text("secret")
        (tmp_path / "visible.txt").write_text("public")
        result = fs.list_directory(str(tmp_path))
        names = {e["name"] for e in result["entries"]}
        assert "visible.txt" in names
        assert ".hidden" not in names

    def test_hidden_files_included_when_requested(self, tmp_path):
        (tmp_path / ".hidden").write_text("secret")
        result = fs.list_directory(str(tmp_path), hidden=True)
        names = {e["name"] for e in result["entries"]}
        assert ".hidden" in names

    def test_max_entries_limit(self, tmp_path):
        for i in range(20):
            (tmp_path / f"file{i:03d}.txt").write_text("x")
        result = fs.list_directory(str(tmp_path), max_entries=5)
        assert result["count"] <= 5
        assert result["truncated"] is True

    def test_nonexistent_dir_returns_error(self, tmp_path):
        result = fs.list_directory(str(tmp_path / "nope"))
        assert "error" in result


class TestCreateDirectory:
    def test_create_single(self, tmp_path):
        d = str(tmp_path / "newdir")
        result = fs.create_directory(d)
        assert result["success"] is True
        assert os.path.isdir(d)

    def test_create_with_parents(self, tmp_path):
        d = str(tmp_path / "a" / "b" / "c")
        result = fs.create_directory(d, parents=True)
        assert result["success"] is True
        assert os.path.isdir(d)

    def test_existing_dir_ok(self, tmp_path):
        result = fs.create_directory(str(tmp_path))
        assert result["success"] is True


class TestDeleteFile:
    def test_delete_file(self, tmp_path):
        f = tmp_path / "del.txt"
        f.write_text("bye")
        result = fs.delete_file(str(f))
        assert result["success"] is True
        assert not f.exists()

    def test_delete_directory(self, tmp_path):
        d = tmp_path / "deldir"
        d.mkdir()
        (d / "file.txt").write_text("x")
        result = fs.delete_file(str(d))
        assert result["success"] is True
        assert not d.exists()

    def test_delete_nonexistent_returns_error(self, tmp_path):
        result = fs.delete_file(str(tmp_path / "nope.txt"))
        assert "error" in result


# ---------------------------------------------------------------------------
# Kopieren & Verschieben
# ---------------------------------------------------------------------------


class TestCopyMove:
    def test_copy_file(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_text("content")
        dst = str(tmp_path / "dst.txt")
        result = fs.copy_file(str(src), dst)
        assert result["success"] is True
        assert os.path.exists(dst)
        assert open(dst).read() == "content"

    def test_move_file(self, tmp_path):
        src = tmp_path / "src.txt"
        src.write_text("moving")
        dst = str(tmp_path / "dst.txt")
        result = fs.move_file(str(src), dst)
        assert result["success"] is True
        assert not src.exists()
        assert open(dst).read() == "moving"

    def test_rename_file(self, tmp_path):
        f = tmp_path / "old.txt"
        f.write_text("rename me")
        result = fs.rename_file(str(f), "new.txt")
        assert result["success"] is True
        assert not f.exists()
        assert (tmp_path / "new.txt").exists()

    def test_rename_rejects_path_separator(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        result = fs.rename_file(str(f), "evil/path.txt")
        assert "error" in result

    def test_copy_directory(self, tmp_workdir, tmp_path):
        dst = str(tmp_path / "copy_dst")
        result = fs.copy_directory(str(tmp_workdir), dst)
        assert result["success"] is True
        assert os.path.exists(os.path.join(dst, "hello.txt"))


# ---------------------------------------------------------------------------
# Suche
# ---------------------------------------------------------------------------


class TestSearchFiles:
    def test_search_by_extension(self, tmp_workdir):
        result = fs.search_files(str(tmp_workdir), pattern="*.txt")
        assert result["success"] is True
        assert result["count"] >= 1
        assert all(r["path"].endswith(".txt") for r in result["results"])

    def test_search_case_insensitive(self, tmp_path):
        (tmp_path / "README.TXT").write_text("x")
        result = fs.search_files(str(tmp_path), pattern="*.txt", case_sensitive=False)
        assert result["count"] >= 1

    def test_search_no_results(self, tmp_workdir):
        result = fs.search_files(str(tmp_workdir), pattern="*.xyz")
        assert result["success"] is True
        assert result["count"] == 0

    def test_search_star_finds_all(self, tmp_workdir):
        result = fs.search_files(str(tmp_workdir), pattern="*")
        assert result["count"] >= 2


class TestGetRecentFiles:
    def test_finds_recently_created(self, tmp_path):
        f = tmp_path / "recent.txt"
        f.write_text("new")
        result = fs.get_recent_files(str(tmp_path), time_range_days=1)
        assert result["success"] is True
        assert result["count"] >= 1


# ---------------------------------------------------------------------------
# Informationen
# ---------------------------------------------------------------------------


class TestGetFileInfo:
    def test_file_info(self, tmp_path):
        f = tmp_path / "info.txt"
        f.write_text("hello")
        result = fs.get_file_info(str(f))
        assert result["success"] is True
        assert result["is_file"] is True
        assert result["is_directory"] is False
        assert result["size_bytes"] == 5

    def test_dir_info(self, tmp_path):
        result = fs.get_file_info(str(tmp_path))
        assert result["is_directory"] is True
        assert result["is_file"] is False


class TestPathExists:
    def test_existing_file(self, tmp_path):
        f = tmp_path / "exists.txt"
        f.write_text("x")
        result = fs.path_exists(str(f))
        assert result["exists"] is True
        assert result["is_file"] is True

    def test_nonexistent(self, tmp_path):
        result = fs.path_exists(str(tmp_path / "nope.txt"))
        assert result["exists"] is False

    def test_null_byte_rejected(self):
        result = fs.path_exists("/tmp/evil\x00.txt")
        assert "error" in result


class TestGetFileHash:
    def test_sha256(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_text("hello")
        result = fs.get_file_hash(str(f))
        assert result["success"] is True
        assert result["algorithm"] == "sha256"
        # Known SHA256 of "hello"
        assert result["hash"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_md5(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_text("hello")
        result = fs.get_file_hash(str(f), algorithm="md5")
        assert result["success"] is True
        assert len(result["hash"]) == 32

    def test_unknown_algorithm(self, tmp_path):
        f = tmp_path / "hash.txt"
        f.write_text("x")
        result = fs.get_file_hash(str(f), algorithm="md999")
        assert "error" in result


# ---------------------------------------------------------------------------
# Archivoperationen
# ---------------------------------------------------------------------------


class TestArchiveOps:
    def test_compress_and_decompress_roundtrip(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.txt").write_text("file a")
        (src / "b.txt").write_text("file b")
        archive = str(tmp_path / "test.zip")
        result = fs.compress_archive(str(src), archive)
        assert result["success"] is True
        assert result["file_count"] == 2

        dst = tmp_path / "dst"
        result = fs.decompress_archive(archive, str(dst))
        assert result["success"] is True
        assert result["extracted_count"] == 2

    def test_compress_single_file(self, tmp_path):
        f = tmp_path / "single.txt"
        f.write_text("one file")
        archive = str(tmp_path / "single.zip")
        result = fs.compress_archive(str(f), archive)
        assert result["success"] is True
        assert result["file_count"] == 1

    def test_invalid_zip_rejected(self, tmp_path):
        bad_zip = tmp_path / "bad.zip"
        bad_zip.write_bytes(b"not a zip file at all")
        result = fs.decompress_archive(str(bad_zip), str(tmp_path / "out"))
        assert "error" in result


# ---------------------------------------------------------------------------
# touch_file / count_entries / get_disk_usage
# ---------------------------------------------------------------------------


class TestMiscTools:
    def test_touch_creates_file(self, tmp_path):
        f = str(tmp_path / "touched.txt")
        result = fs.touch_file(f)
        assert result["success"] is True
        assert result["created"] is True
        assert os.path.exists(f)

    def test_touch_updates_existing(self, tmp_path):
        f = tmp_path / "existing.txt"
        f.write_text("x")
        old_mtime = f.stat().st_mtime
        time.sleep(0.05)
        result = fs.touch_file(str(f))
        assert result["success"] is True

    def test_count_entries(self, tmp_workdir):
        result = fs.count_entries(str(tmp_workdir))
        assert result["success"] is True
        assert result["file_count"] >= 1
        assert result["dir_count"] >= 1

    def test_count_entries_recursive(self, tmp_workdir):
        result = fs.count_entries(str(tmp_workdir), recursive=True)
        assert result["success"] is True
        assert result["file_count"] >= 2  # hello.txt + nested.txt

    def test_get_disk_usage(self, tmp_path):
        result = fs.get_disk_usage(str(tmp_path))
        assert result["success"] is True
        assert result["total_bytes"] > 0

    def test_get_working_directory(self):
        result = fs.get_working_directory()
        assert result["success"] is True
        assert os.path.isdir(result["cwd"])

    def test_empty_directory_keep_structure(self, tmp_workdir):
        result = fs.empty_directory(str(tmp_workdir), keep_structure=True)
        assert result["success"] is True
        assert result["deleted_files"] >= 1
        # Verzeichnis selbst muss noch existieren
        assert os.path.isdir(str(tmp_workdir))
