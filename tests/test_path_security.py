"""
Sicherheitstests für Pfad-Validierung, ZIP-Schutz und blockierte Systempfade.
Diese Tests stellen sicher, dass kritische Sicherheitsmechanismen korrekt funktionieren.
"""

import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import lokales_dateisystem as fs


# ---------------------------------------------------------------------------
# Null-Byte-Schutz
# ---------------------------------------------------------------------------


class TestNullByteProtection:
    def test_detect_null_byte(self):
        assert fs._has_null_byte("path\x00evil") is True

    def test_null_at_start(self):
        assert fs._has_null_byte("\x00etc/shadow") is True

    def test_null_at_end(self):
        assert fs._has_null_byte("/tmp/file\x00") is True

    def test_clean_path(self):
        assert fs._has_null_byte("/tmp/normal_file.txt") is False

    def test_empty_string(self):
        assert fs._has_null_byte("") is False

    def test_is_path_safe_rejects_null(self):
        ok, reason = fs.is_path_safe("/tmp/file\x00.txt")
        assert ok is False
        assert "Null" in reason

    def test_is_path_blocked_rejects_null(self):
        assert fs.is_path_blocked("/tmp/file\x00.txt") is True


# ---------------------------------------------------------------------------
# Blockierte Systempfade
# ---------------------------------------------------------------------------


class TestBlockedPaths:
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/sudoers.d",
            "/etc/ssh",
            "/proc/kcore",
            "/proc/sys",
            "/sys",
            "/dev",
            "/root/.ssh",
            "/private/etc/sudoers",
            "/private/etc/master.passwd",
        ],
    )
    def test_unix_blocked_paths(self, path):
        """Kritische Unix/macOS-Systempfade müssen blockiert sein."""
        assert fs.is_path_blocked(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Windows\System32\config",
            r"C:\Windows\System32\drivers",
            r"C:\$Recycle.Bin",
            r"C:\System Volume Information",
        ],
    )
    def test_windows_blocked_paths(self, path):
        """Kritische Windows-Systempfade müssen blockiert sein."""
        assert fs.is_path_blocked(path) is True

    def test_subdirectory_of_blocked_is_blocked(self):
        """Unterverzeichnisse blockierter Pfade müssen ebenfalls blockiert sein."""
        assert fs.is_path_blocked("/etc/shadow/anything") is True
        assert fs.is_path_blocked("/dev/sda") is True
        assert fs.is_path_blocked("/sys/kernel") is True

    def test_safe_paths_not_blocked(self, tmp_path):
        """Normale Benutzerpfade dürfen nicht blockiert sein."""
        assert fs.is_path_blocked(str(tmp_path)) is False
        assert fs.is_path_blocked("/tmp/myfile.txt") is False
        assert fs.is_path_blocked(os.path.expanduser("~/documents")) is False

    def test_is_path_safe_rejects_blocked(self):
        ok, reason = fs.is_path_safe("/etc/shadow")
        assert ok is False

    def test_is_path_safe_allows_tmp(self, tmp_path):
        ok, _ = fs.is_path_safe(str(tmp_path))
        assert ok is True


# ---------------------------------------------------------------------------
# ZIP-Slip-Schutz  (_is_safe_zip_member)
# ---------------------------------------------------------------------------


class TestZipSlipProtection:
    def _member(self, name: str, is_symlink: bool = False) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(name)
        if is_symlink:
            # Setze Unix-Symlink-Bit im external_attr
            info.external_attr = 0xA1ED0000
        return info

    def test_path_traversal_dotdot(self):
        m = self._member("../../../etc/shadow")
        safe, why = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is False
        assert "Traversal" in why or "Path" in why

    def test_absolute_path_rejected(self):
        m = self._member("/etc/shadow")
        safe, why = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is False
        assert "absolut" in why.lower() or "Absolut" in why

    def test_symlink_in_archive_rejected(self):
        m = self._member("legit.txt", is_symlink=True)
        safe, why = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is False
        assert "Symlink" in why

    def test_null_byte_in_filename(self):
        """_is_safe_zip_member muss Null-Bytes im Dateinamen ablehnen.
        Hinweis: zipfile.ZipInfo() truncates the filename at null bytes.
        We therefore test _is_safe_zip_member directly with a null byte name.
        """
        import zipfile as _zf
        member = _zf.ZipInfo.__new__(_zf.ZipInfo)
        member.filename = "file\x00.txt"
        member.external_attr = 0
        safe, why = fs._is_safe_zip_member(member, "/safe/dest")
        assert safe is False
        assert "Null" in why

    def test_safe_file_passes(self):
        m = self._member("folder/file.txt")
        safe, _ = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is True

    def test_safe_nested_file_passes(self):
        m = self._member("a/b/c/deep.txt")
        safe, _ = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is True

    def test_windows_drive_letter_rejected(self):
        m = self._member("C:evil.txt")
        safe, why = fs._is_safe_zip_member(m, "/safe/dest")
        assert safe is False


# ---------------------------------------------------------------------------
# ZIP-Bomb-Schutz  (decompress_archive)
# ---------------------------------------------------------------------------


class TestZipBombProtection:
    def test_too_many_files_rejected(self, tmp_path):
        """Archive mit mehr als MAX_ZIP_FILES Dateien müssen abgelehnt werden."""
        archive = tmp_path / "bomb.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for i in range(fs.MAX_ZIP_FILES + 1):
                zf.writestr(f"file_{i:05d}.txt", "x")
        dest = tmp_path / "out"
        result = fs.decompress_archive(str(archive), str(dest))
        assert "error" in result
        assert "Dateien" in result["error"] or "files" in result["error"].lower()

    def test_legitimate_archive_extracted(self, tmp_path):
        """Ein normales Archiv muss korrekt entpackt werden."""
        archive = tmp_path / "legit.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("hello.txt", "hello world")
            zf.writestr("subdir/world.txt", "world")
        dest = tmp_path / "out"
        result = fs.decompress_archive(str(archive), str(dest))
        assert result.get("success") is True
        assert result["extracted_count"] == 2
        assert (dest / "hello.txt").read_text() == "hello world"

    def test_zip_slip_rejected_during_extraction(self, tmp_path):
        """ZIP-Slip-Angriff bei der Extraktion muss abgefangen werden."""
        archive = tmp_path / "slip.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../../../../tmp/pwned.txt", "pwned")
        dest = tmp_path / "out"
        result = fs.decompress_archive(str(archive), str(dest))
        # Entweder werden schlechte Einträge abgelehnt oder alles schlägt fehl
        if result.get("success"):
            assert result.get("rejected_count", 0) > 0
        else:
            assert "error" in result


# ---------------------------------------------------------------------------
# File-Size-Limits
# ---------------------------------------------------------------------------


class TestFileSizeLimits:
    def test_read_file_enforces_size_limit(self, tmp_path, monkeypatch):
        """read_file muss Dateien über dem Limit ablehnen."""
        f = tmp_path / "big.txt"
        f.write_text("x")
        # Simuliere eine zu große Datei durch Monkeypatching
        monkeypatch.setattr(os.path, "getsize", lambda p: fs.MAX_FILE_READ_SIZE + 1)
        result = fs.read_file(str(f))
        assert "error" in result
        assert "gross" in result["error"].lower() or "limit" in result["error"].lower()

    def test_write_file_enforces_size_limit(self, tmp_path):
        """write_file muss Inhalte über dem Limit ablehnen."""
        huge_content = "x" * (fs.MAX_FILE_WRITE_SIZE + 1)
        result = fs.write_file(str(tmp_path / "huge.txt"), huge_content)
        assert "error" in result


# ---------------------------------------------------------------------------
# chmod - Restriktive Bits
# ---------------------------------------------------------------------------


class TestChmodRestrictions:
    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    def test_chmod_rejects_world_writable(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("x")
        result = fs.chmod_file(str(f), "777")
        assert "error" in result
        assert "Bit" in result["error"] or "erlaubt" in result["error"] or "Maximum" in result["error"]

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    def test_chmod_rejects_setuid(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("x")
        result = fs.chmod_file(str(f), "4755")
        assert "error" in result

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    def test_chmod_allows_755(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("x")
        result = fs.chmod_file(str(f), "755")
        assert result.get("success") is True

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod semantics differ on Windows")
    def test_chmod_allows_644(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("x")
        result = fs.chmod_file(str(f), "644")
        assert result.get("success") is True
