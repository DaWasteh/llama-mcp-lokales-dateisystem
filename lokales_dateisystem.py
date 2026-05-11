"""
MCP Server für lokalen Dateisystem-Zugriff (Windows/Linux/macOS)
Kompatibel mit llama.cpp (getestet mit b9010) WebUI via Streamable HTTP Transport.

Tool-Schemas werden von FastMCP automatisch aus Type Hints + Docstrings
generiert -> kein manuelles inputSchema mehr nötig.

Erweiterte Features:
- Dateioperationen: lesen, schreiben, kopieren, verschieben, löschen, umbenennen
- Verzeichnisoperationen: auflisten, baumansicht, erstellen, löschen
- Archivoperationen: komprimieren (ZIP), entpacken (ZIP)
- Binärdateien: Bilder, Medien direkt als Base64 lesbar
- Symlinks: erstellen und auflösen
- Systeminformationen: Festplattenauslastung, Arbeitsverzeichnis, Root-Pfade
- Zeitstempel: touch_file aktualisiert mtime/atime
"""

import os
import tempfile
import sys
import io
import shutil
import platform
import fnmatch
import base64
import argparse
import zipfile
import time
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Tuple

# ============================================================
# Stderr auf UTF-8 zwingen (Windows-Konsole nutzt sonst cp1252)
# ============================================================
if isinstance(sys.stderr, io.TextIOWrapper):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ============================================================
# MCP SDK Import (FastMCP - High-Level API)
# ============================================================
try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"FEHLER: MCP SDK nicht korrekt installiert. ({e})", file=sys.stderr)
    print("Führe aus: pip install --upgrade mcp", file=sys.stderr)
    sys.exit(1)


# ============================================================
# Konfiguration
# ============================================================

SERVER_NAME = "filesystem-server"

DEFAULT_ROOT = os.environ.get("MCP_FILESYSTEM_ROOT", str(Path.home()))

# Blockierte Pfade - Systemkritische Verzeichnisse
BLOCKED_PATHS = {
    r"C:\Windows\System32\config",
    r"C:\Program Files\WindowsApps",
    # Linux/macOS Schutz
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/kcore",
}

# Erlaubte Root-Pfade (für get_allowed_roots)
ALLOWED_ROOTS = [DEFAULT_ROOT]

IS_WINDOWS = platform.system() == "Windows"


def is_path_blocked(path: str) -> bool:
    """Prüft, ob ein Pfad in der Blocked-Liste ist (case-insensitive auf Windows)."""
    norm = os.path.normpath(path)
    if IS_WINDOWS:
        norm = norm.lower()
    for blocked in BLOCKED_PATHS:
        nb = os.path.normpath(blocked)
        if IS_WINDOWS:
            nb = nb.lower()
        if norm.startswith(nb):
            return True
    return False


def get_file_extension(path: str) -> str:
    """Gibt die Dateiendung zurück (kleingeschrieben)."""
    return Path(path).suffix.lower()


def is_binary_file(path: str) -> bool:
    """Prüft, ob eine Datei binär ist basierend auf der Erweiterung."""
    binary_extensions = {
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp', '.svg', '.ico',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
        '.exe', '.dll', '.so', '.dylib', '.app', '.dmg', '.iso',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.pyc', '.pyo', '.class', '.o', '.a', '.lib',
        '.db', '.sqlite', '.sqlite3',
        '.woff', '.woff2', '.ttf', '.otf',
        '.cr2', '.nef', '.arw', '.dng', '.heic', '.heif',
    }
    return get_file_extension(path) in binary_extensions


# ============================================================
# FastMCP Server-Instanz erstellen
# ============================================================

mcp = FastMCP(SERVER_NAME)


# ============================================================
# Tools (Filesystem-Operationen)
# ============================================================

@mcp.tool()
def read_file(path: str) -> dict:
    """Liest den Inhalt einer Datei und gibt den Text zurück.

    Args:
        path: Absoluter oder relativer Pfad zur Datei.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            content = f.read()
        return {
            "success": True,
            "path": path,
            "content": content,
            "size_bytes": os.path.getsize(abs_path),
            "lines": len(content.splitlines()),
        }
    except FileNotFoundError:
        return {"error": f"Datei nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except UnicodeDecodeError:
        try:
            with open(abs_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
            return {
                "success": True,
                "path": path,
                "content": b64,
                "binary": True,
                "size_bytes": os.path.getsize(abs_path),
            }
        except Exception as e:
            return {"error": f"Fehler beim Lesen: {str(e)}"}


@mcp.tool()
def read_file_binary(path: str) -> dict:
    """Liest eine Datei als Binärdaten und gibt sie als Base64-codierten String zurück.

    Nützlich für Bilder, Audio, Video und andere Binärdateien.

    Args:
        path: Absoluter oder relativer Pfad zur Datei.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        with open(abs_path, "rb") as f:
            data = f.read()
        b64 = base64.b64encode(data).decode("ascii")
        return {
            "success": True,
            "path": path,
            "content": b64,
            "binary": True,
            "size_bytes": len(data),
            "encoding": "base64",
            "extension": get_file_extension(path),
        }
    except FileNotFoundError:
        return {"error": f"Datei nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Lesen: {str(e)}"}


@mcp.tool()
def write_file(path: str, content: str, append: bool = False, encoding: str = "utf-8") -> dict:
    """Schreibt Text in eine Datei.

    Args:
        path: Zielpfad für die Datei.
        content: Inhalt, der geschrieben werden soll.
        append: True um an bestehende Datei anzuhängen, False zum Überschreiben.
        encoding: Zeichencodierung (Default: utf-8).
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        mode = "a" if append else "w"
        with open(abs_path, mode, encoding=encoding) as f:
            f.write(content)
        return {
            "success": True,
            "path": path,
            "bytes_written": len(content.encode(encoding)),
            "mode": "append" if append else "write",
            "encoding": encoding,
        }
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Schreiben: {str(e)}"}


@mcp.tool()
def write_file_binary(path: str, content: str, encoding: str = "base64") -> dict:
    """Schreibt Binärdaten in eine Datei (Base64-codiert).

    Args:
        path: Zielpfad für die Datei.
        content: Base64-codierte Binärdaten.
        encoding: Encoding der Eingabe (Default: base64).
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        if encoding == "base64":
            data = base64.b64decode(content)
        else:
            data = content.encode(encoding)
        with open(abs_path, "wb") as f:
            f.write(data)
        return {
            "success": True,
            "path": path,
            "bytes_written": len(data),
        }
    except Exception as e:
        return {"error": f"Fehler beim Schreiben: {str(e)}"}


@mcp.tool()
def list_directory(path: str, recursive: bool = False, hidden: bool = False) -> dict:
    """Listet alle Dateien und Unterverzeichnisse eines Verzeichnisses auf.

    Args:
        path: Pfad zum Verzeichnis.
        recursive: Wenn True, werden auch Unterverzeichnisse rekursiv durchsucht.
        hidden: Wenn True, werden versteckte Dateien (.dotfiles) angezeigt.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        entries = []

        if recursive:
            for root, dirs, files in os.walk(abs_path):
                # Versteckte Ordner filtern
                if not hidden:
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    files = [f for f in files if not f.startswith('.')]
                
                dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
                for d in dirs:
                    full = os.path.join(root, d)
                    try:
                        st = os.stat(full)
                        entries.append({
                            "name": os.path.relpath(full, abs_path),
                            "is_directory": True,
                            "size": 0,
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        })
                    except (PermissionError, FileNotFoundError):
                        pass
                for f in files:
                    full = os.path.join(root, f)
                    try:
                        st = os.stat(full)
                        entries.append({
                            "name": os.path.relpath(full, abs_path),
                            "is_directory": False,
                            "size": st.st_size,
                            "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        })
                    except (PermissionError, FileNotFoundError):
                        pass
        else:
            for entry in sorted(os.scandir(abs_path), key=lambda e: (not e.is_dir(), e.name)):
                # Versteckte Dateien filtern
                if not hidden and entry.name.startswith('.'):
                    continue
                try:
                    st = entry.stat()
                    entries.append({
                        "name": entry.name,
                        "is_directory": entry.is_dir(),
                        "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    })
                except (PermissionError, FileNotFoundError):
                    pass

        return {
            "success": True,
            "path": path,
            "recursive": recursive,
            "hidden": hidden,
            "entries": entries,
            "count": len(entries),
        }
    except FileNotFoundError:
        return {"error": f"Verzeichnis nicht gefunden: {path}"}
    except NotADirectoryError:
        return {"error": f"Kein Verzeichnis: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}


@mcp.tool()
def get_tree(path: str, max_depth: int = 5, hidden: bool = False) -> dict:
    """Gibt einen Verzeichnisbaum mit Einrückung zurück.

    Args:
        path: Startverzeichnis für den Baum.
        max_depth: Maximale Tiefe des Baums (Default: 5).
        hidden: Wenn True, werden versteckte Dateien angezeigt.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        lines = []
        base_depth = abs_path.rstrip(os.sep) + os.sep

        for root, dirs, files in os.walk(abs_path):
            # Tiefe berechnen
            current_depth = root[len(base_depth):].count(os.sep)
            if current_depth >= max_depth:
                dirs.clear()
                continue

            # Versteckte Ordner filtern
            if not hidden:
                dirs[:] = sorted([d for d in dirs if not d.startswith('.')])
                files = sorted([f for f in files if not f.startswith('.')])
            else:
                dirs[:] = sorted(dirs)
                files = sorted(files)

            # Verzeichnis einfügen
            indent = "  " * current_depth
            lines.append(f"{indent}📁 {os.path.basename(root)}/")

            # Dateien und Unterverzeichnisse
            for d in dirs:
                child_indent = "  " * (current_depth + 1)
                lines.append(f"{child_indent}📁 {d}/")
            for f in files:
                child_indent = "  " * (current_depth + 1)
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                    lines.append(f"{child_indent}📄 {f} ({size} Bytes)")
                except (PermissionError, FileNotFoundError):
                    lines.append(f"{child_indent}📄 {f}")

        return {
            "success": True,
            "path": path,
            "max_depth": max_depth,
            "hidden": hidden,
            "tree": "\n".join(lines),
        }
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def copy_file(source: str, destination: str) -> dict:
    """Kopiert eine Datei von einer Quelle zu einem Ziel.

    Args:
        source: Quellpfad.
        destination: Zielpfad.
    """
    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)
    if is_path_blocked(abs_src) or is_path_blocked(abs_dst):
        return {"error": "Zugriff verweigert für Quelle oder Ziel"}

    try:
        shutil.copy2(abs_src, abs_dst)
        return {
            "success": True,
            "source": source,
            "destination": destination,
            "bytes_copied": os.path.getsize(abs_dst),
        }
    except Exception as e:
        return {"error": f"Kopierfehler: {str(e)}"}


@mcp.tool()
def copy_directory(source: str, destination: str, preserve_times: bool = True) -> dict:
    """Kopiert ein gesamtes Verzeichnis rekursiv.

    Args:
        source: Quellverzeichnis.
        destination: Zielverzeichnis.
        preserve_times: True um Zeitstempel zu behalten.
    """
    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)
    if is_path_blocked(abs_src) or is_path_blocked(abs_dst):
        return {"error": "Zugriff verweigert für Quelle oder Ziel"}

    try:
        if not os.path.exists(abs_src):
            return {"error": f"Quelle existiert nicht: {source}"}
        
        if os.path.isfile(abs_src):
            return {"error": f"Quelle ist eine Datei, kein Verzeichnis: {source}"}
        
        if preserve_times:
            shutil.copytree(abs_src, abs_dst, dirs_exist_ok=True)
        else:
            # Manuell kopieren ohne Zeitstempel
            os.makedirs(abs_dst, exist_ok=True)
            for item in os.listdir(abs_src):
                s = os.path.join(abs_src, item)
                d = os.path.join(abs_dst, item)
                if os.path.isdir(s):
                    copy_directory(s, d, preserve_times=False)
                else:
                    shutil.copy2(s, d)
        
        return {
            "success": True,
            "source": source,
            "destination": destination,
        }
    except Exception as e:
        return {"error": f"Kopierfehler: {str(e)}"}


@mcp.tool()
def move_file(source: str, destination: str) -> dict:
    """Verschiebt oder benennt eine Datei um.

    Args:
        source: Quellpfad.
        destination: Zielpfad.
    """
    abs_src = os.path.abspath(source)
    abs_dst = os.path.abspath(destination)
    if is_path_blocked(abs_src) or is_path_blocked(abs_dst):
        return {"error": "Zugriff verweigert für Quelle oder Ziel"}

    try:
        shutil.move(abs_src, abs_dst)
        return {"success": True, "source": source, "destination": destination}
    except Exception as e:
        return {"error": f"Verschiebefehler: {str(e)}"}


@mcp.tool()
def rename_file(path: str, new_name: str) -> dict:
    """Benennt eine Datei oder ein Verzeichnis um.

    Args:
        path: Aktueller Pfad der Datei/des Verzeichnisses.
        new_name: Neuer Name (nur Dateiname, kein Pfad).
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        parent = os.path.dirname(abs_path)
        new_path = os.path.join(parent, new_name)
        
        if os.path.exists(abs_path):
            os.rename(abs_path, new_path)
            return {
                "success": True,
                "old_path": path,
                "new_path": new_name,
                "absolute_new_path": new_path,
            }
        else:
            return {"error": f"Pfad nicht gefunden: {path}"}
    except FileExistsError:
        return {"error": f"Ziel existiert bereits: {new_name}"}
    except Exception as e:
        return {"error": f"Umbenennungsfehler: {str(e)}"}


@mcp.tool()
def delete_file(path: str) -> dict:
    """Löscht eine Datei oder ein Verzeichnis (rekursiv).

    Args:
        path: Pfad zur zu löschenden Datei oder zum Ordner.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        was_dir = os.path.isdir(abs_path)
        if was_dir:
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        return {"success": True, "path": path, "type": "directory" if was_dir else "file"}
    except FileNotFoundError:
        return {"error": f"Nicht gefunden: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Löschen: {str(e)}"}


@mcp.tool()
def create_directory(path: str, parents: bool = True) -> dict:
    """Erstellt ein neues Verzeichnis.

    Args:
        path: Pfad zum neuen Verzeichnis.
        parents: True um Eltern-Verzeichnisse automatisch anzulegen.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        if parents:
            os.makedirs(abs_path, exist_ok=True)
        else:
            os.mkdir(abs_path)
        return {"success": True, "path": path, "created": True, "parents": parents}
    except FileExistsError:
        return {"success": True, "path": path, "created": False, "note": "existierte bereits"}
    except FileNotFoundError:
        return {"error": f"Eltern-Verzeichnis fehlt (parents=False): {path}"}
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def search_files(path: str, pattern: str = "*", max_results: int = 100, case_sensitive: bool = False) -> dict:
    """Durchsucht Dateien rekursiv mit einem Glob-Muster.

    Args:
        path: Startverzeichnis für die Suche.
        pattern: Glob-Muster, z.B. '*.txt' oder 'config*'.
        max_results: Maximale Anzahl Ergebnisse.
        case_sensitive: False (standard) für case-insensitive Suche auf Windows.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        results = []
        for root, dirs, files in os.walk(abs_path):
            dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
            for name in files:
                if case_sensitive:
                    match = fnmatch.fnmatch(name, pattern)
                else:
                    match = fnmatch.fnmatch(name.lower(), pattern.lower())
                if match:
                    full = os.path.join(root, name)
                    try:
                        results.append({
                            "path": os.path.relpath(full, abs_path),
                            "absolute_path": full,
                            "size": os.path.getsize(full),
                            "modified": datetime.fromtimestamp(os.path.getmtime(full)).isoformat(),
                        })
                        if len(results) >= max_results:
                            break
                    except (PermissionError, FileNotFoundError):
                        pass
            if len(results) >= max_results:
                break

        return {
            "success": True,
            "path": path,
            "pattern": pattern,
            "case_sensitive": case_sensitive,
            "results": results,
            "count": len(results),
        }
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_file_info(path: str) -> dict:
    """Gibt Details über eine Datei oder einen Ordner zurück (Größe, Datum, etc.).

    Args:
        path: Pfad zur Datei oder zum Ordner.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        stat = os.stat(abs_path)
        return {
            "success": True,
            "path": path,
            "absolute_path": abs_path,
            "is_directory": os.path.isdir(abs_path),
            "is_file": os.path.isfile(abs_path),
            "is_symlink": os.path.islink(abs_path),
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "extension": get_file_extension(abs_path),
        }
    except FileNotFoundError:
        return {"error": f"Nicht gefunden: {path}"}
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def count_entries(path: str, recursive: bool = False) -> dict:
    """Zählt Dateien und Verzeichnisse in einem Verzeichnis.

    Args:
        path: Pfad zum Verzeichnis.
        recursive: Wenn True, werden Unterverzeichnisse rekursiv gezählt.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        file_count = 0
        dir_count = 0
        total_size = 0

        if recursive:
            for root, dirs, files in os.walk(abs_path):
                dir_count += len(dirs)
                for f in files:
                    file_count += 1
                    full = os.path.join(root, f)
                    try:
                        total_size += os.path.getsize(full)
                    except (PermissionError, FileNotFoundError):
                        pass
        else:
            entries = os.listdir(abs_path)
            for entry in entries:
                full = os.path.join(abs_path, entry)
                if os.path.isdir(full):
                    dir_count += 1
                else:
                    file_count += 1
                    try:
                        total_size += os.path.getsize(full)
                    except (PermissionError, FileNotFoundError):
                        pass

        return {
            "success": True,
            "path": path,
            "recursive": recursive,
            "file_count": file_count,
            "dir_count": dir_count,
            "total_count": file_count + dir_count,
            "total_size_bytes": total_size,
        }
    except FileNotFoundError:
        return {"error": f"Verzeichnis nicht gefunden: {path}"}
    except NotADirectoryError:
        return {"error": f"Kein Verzeichnis: {path}"}
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}


@mcp.tool()
def touch_file(path: str, times: Optional[List[float]] = None) -> dict:
    """Aktualisiert den Zeitstempel einer Datei oder erstellt sie falls nicht existent.

    Args:
        path: Pfad zur Datei.
        times: Liste [mtime, atime] als Unix-Timestamps (optional). 
               Wenn nicht angegeben, wird aktuelle Zeit verwendet.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        created = not os.path.exists(abs_path)
        
        if times and len(times) == 2:
            mtime, atime = times
            os.utime(abs_path, (atime, mtime))
        else:
            # Aktuelle Zeit setzen
            now = time.time()
            os.utime(abs_path, (now, now))
        
        return {
            "success": True,
            "path": path,
            "created": created,
            "new_mtime": datetime.fromtimestamp(os.path.getmtime(abs_path)).isoformat(),
        }
    except FileNotFoundError:
        # Datei erstellen wenn nicht existent
        try:
            Path(abs_path).touch()
            return {
                "success": True,
                "path": path,
                "created": True,
                "new_mtime": datetime.fromtimestamp(os.path.getmtime(abs_path)).isoformat(),
            }
        except Exception as e:
            return {"error": f"Fehler: {str(e)}"}
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def compress_archive(path: str, archive_path: str, compression: str = "DEFLATED") -> dict:
    """Komprimiert eine Datei oder ein Verzeichnis als ZIP-Archiv.

    Args:
        path: Zu komprimierende Datei oder Verzeichnis.
        archive_path: Pfad für das ZIP-Archiv (endet auf .zip).
        compression: Komprimierungsmethode: "STORED" (keine), "DEFLATED" (standard).
    """
    abs_path = os.path.abspath(path)
    abs_archive = os.path.abspath(archive_path)
    
    if is_path_blocked(abs_path) or is_path_blocked(abs_archive):
        return {"error": "Zugriff verweigert für Quelle oder Ziel"}

    try:
        if not os.path.exists(abs_path):
            return {"error": f"Quelle nicht gefunden: {path}"}

        # Komprimierungsmethode wählen
        if compression == "DEFLATED":
            compress_type = zipfile.ZIP_DEFLATED
        else:
            compress_type = zipfile.ZIP_STORED

        with zipfile.ZipFile(abs_archive, 'w', compression=compress_type) as zipf:
            if os.path.isdir(abs_path):
                # Verzeichnis rekursiv hinzufügen
                for root, dirs, files in os.walk(abs_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, os.path.dirname(abs_path))
                        zipf.write(file_path, arcname)
            else:
                # Einzelne Datei hinzufügen
                arcname = os.path.basename(abs_path)
                zipf.write(abs_path, arcname)

        return {
            "success": True,
            "source": path,
            "archive": archive_path,
            "archive_size": os.path.getsize(abs_archive),
            "compression": compression,
        }
    except Exception as e:
        return {"error": f"Komprimierungsfehler: {str(e)}"}


@mcp.tool()
def decompress_archive(archive_path: str, destination: str) -> dict:
    """Entpackt ein ZIP-Archiv in ein Zielverzeichnis.

    Args:
        archive_path: Pfad zum ZIP-Archiv.
        destination: Zielverzeichnis zum Entpacken.
    """
    abs_archive = os.path.abspath(archive_path)
    abs_dest = os.path.abspath(destination)
    
    if is_path_blocked(abs_archive) or is_path_blocked(abs_dest):
        return {"error": "Zugriff verweigert für Archiv oder Ziel"}

    try:
        if not os.path.exists(abs_archive):
            return {"error": f"Archiv nicht gefunden: {archive_path}"}
        
        if not zipfile.is_zipfile(abs_archive):
            return {"error": f"Keine gültige ZIP-Datei: {archive_path}"}
        
        os.makedirs(abs_dest, exist_ok=True)
        
        with zipfile.ZipFile(abs_archive, 'r') as zipf:
            zipf.extractall(abs_dest)
            files = zipf.namelist()
        
        return {
            "success": True,
            "archive": archive_path,
            "destination": destination,
            "extracted_count": len(files),
            "files": files,
        }
    except Exception as e:
        return {"error": f"Entpackfehler: {str(e)}"}


@mcp.tool()
def create_symlink(path: str, target: str, is_directory: bool = False) -> dict:
    """Erstellt einen Symlink (Symbolic Link).

    Args:
        path: Pfad für den neuen Symlink.
        target: Ziel, auf das der Symlink zeigt.
        is_directory: True wenn das Ziel ein Verzeichnis ist.
    """
    abs_path = os.path.abspath(path)
    abs_target = os.path.abspath(target)
    
    if is_path_blocked(abs_path) or is_path_blocked(abs_target):
        return {"error": "Zugriff verweigert für Symlink oder Ziel"}

    try:
        if os.path.exists(abs_path) or os.path.islink(abs_path):
            return {"error": f"Symlink existiert bereits: {path}"}
        
        if IS_WINDOWS:
            if is_directory:
                os.symlink(abs_target, abs_path, target_is_directory=True)
            else:
                os.symlink(abs_target, abs_path)
        else:
            os.symlink(abs_target, abs_path)
        
        return {
            "success": True,
            "symlink": path,
            "target": target,
            "absolute_target": abs_target,
        }
    except PermissionError:
        return {"error": "Symlinks erfordern Administratorrechte auf Windows"}
    except Exception as e:
        return {"error": f"Symlink-Fehler: {str(e)}"}


@mcp.tool()
def resolve_symlink(path: str) -> dict:
    """Löst einen Symlink auf und gibt das Ziel zurück.

    Args:
        path: Pfad zum Symlink.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        if not os.path.islink(abs_path):
            return {"error": f"Kein Symlink: {path}"}
        
        target = os.readlink(abs_path)
        real_path = os.path.realpath(abs_path)
        
        return {
            "success": True,
            "symlink": path,
            "target": target,
            "real_path": real_path,
            "target_exists": os.path.exists(real_path),
        }
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_disk_usage(path: str = ".") -> dict:
    """Gibt die Festplattenauslastung für das Laufwerk zurück.

    Args:
        path: Pfad auf dem das Laufwerk geprüft werden soll (Default: aktuelles Verzeichnis).
    """
    abs_path = os.path.abspath(path)
    
    try:
        if IS_WINDOWS:
            # Windows: free/total space ermitteln
            _, total_bytes, free_bytes = shutil.disk_usage(abs_path)
        else:
            # Linux/macOS: statvfs
            # Using sys.platform check to avoid Windows type checker errors
            if sys.platform == "win32":
                _, total_bytes, free_bytes = shutil.disk_usage(abs_path)
            else:
                _stat = os.statvfs(abs_path)
                total_bytes = _stat.f_frsize * _stat.f_blocks
                free_bytes = _stat.f_frsize * _stat.f_bavail

        used_bytes = total_bytes - free_bytes
        percent_used = (used_bytes / total_bytes * 100) if total_bytes > 0 else 0

        def format_size(size_bytes: float) -> str:
            """Formatiert Bytes in eine lesbare Größe."""
            size = float(size_bytes)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if size < 1024.0:
                    return f"{size:.2f} {unit}"
                size /= 1024.0
            return f"{size:.2f} PB"

        return {
            "success": True,
            "path": path,
            "total": format_size(total_bytes),
            "used": format_size(used_bytes),
            "free": format_size(free_bytes),
            "used_percent": f"{percent_used:.1f}%",
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
        }
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_allowed_roots() -> dict:
    """Gibt die konfigurierten Root-Pfade zurück.

    Zeigt welche Verzeichnisse der Serverzugriff erlaubt sind.
    """
    return {
        "success": True,
        "default_root": DEFAULT_ROOT,
        "allowed_roots": ALLOWED_ROOTS,
        "blocked_paths": list(BLOCKED_PATHS),
        "environment_root": os.environ.get("MCP_FILESYSTEM_ROOT", "nicht gesetzt"),
    }


@mcp.tool()
def get_working_directory() -> dict:
    """Gibt das aktuelle Arbeitsverzeichnis und System-Informationen zurück."""
    return {
        "success": True,
        "cwd": os.getcwd(),
        "home": str(Path.home()),
        "system": platform.system(),
        "python_version": platform.python_version(),
    }


# ============================================================
# Erweiterte Dateisystem-Tools
# ============================================================

@mcp.tool()
def get_file_hash(path: str, algorithm: str = "sha256") -> dict:
   """Berechnet den Hash-Wert einer Datei.
   
   Args:
       path: Pfad zur Datei.
       algorithm: Hash-Algorithm: "md5", "sha1", "sha256", "sha512" (Default: sha256).
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   import hashlib
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Datei nicht gefunden: {path}"}
       
       if os.path.isdir(abs_path):
           return {"error": f"Keine Datei (Verzeichnis): {path}"}
       
       h = hashlib.new(algorithm)
       with open(abs_path, "rb") as f:
           while True:
               chunk = f.read(8192)
               if not chunk:
                   break
               h.update(chunk)
       
       return {
           "success": True,
           "path": path,
           "algorithm": algorithm,
           "hash": h.hexdigest(),
           "size_bytes": os.path.getsize(abs_path),
       }
   except ValueError:
       return {"error": f"Unbekannter Algorithmus: {algorithm}. Verwende: md5, sha1, sha256, sha512"}
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_file_permissions(path: str) -> dict:
   """Gibt die Dateiberechtigungen zurück.
   
   Args:
       path: Pfad zur Datei oder zum Verzeichnis.
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Nicht gefunden: {path}"}
       
       stat = os.stat(abs_path)
       mode = stat.st_mode
       
       def format_perms(mode_val, flag):
           r = "r" if mode_val & flag else "-"
           w = "w" if mode_val & (flag >> 1) else "-"
           x = "x" if mode_val & (flag >> 2) else "-"
           return f"{r}{w}{x}"
       
       user = format_perms(mode, 0o400) + format_perms(mode, 0o200) + format_perms(mode, 0o100)
       group = format_perms(mode, 0o040) + format_perms(mode, 0o020) + format_perms(mode, 0o010)
       other = format_perms(mode, 0o004) + format_perms(mode, 0o002) + format_perms(mode, 0o001)
       
       result = {
           "success": True,
           "path": path,
           "octal": oct(mode & 0o777),
           "human": f"{user}{group}{other}",
           "user": user,
           "group": group,
           "other": other,
       }
       
       if IS_WINDOWS:
           result["windows_acl"] = True
           result["note"] = "Windows verwendet ACL statt Unix-Berechtigungen"
       
       return result
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def chmod_file(path: str, mode: str) -> dict:
   """Ändert die Dateiberechtigungen.
   
   Args:
       path: Pfad zur Datei oder zum Verzeichnis.
       mode: Octal-Modus, z.B. "755", "644", "700".
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Nicht gefunden: {path}"}
       
       mode_int = int(mode, 8)
       os.chmod(abs_path, mode_int)
       
       return {
           "success": True,
           "path": path,
           "new_mode": oct(mode_int),
           "note": "Berechtigungen geändert",
       }
   except ValueError:
       return {"error": f"Ungültiger Octal-Modus: {mode}. Verwende z.B. 755, 644, 700"}
   except PermissionError:
       return {"error": f"Keine Berechtigung zum Ändern: {path}"}
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def create_hardlink(path: str, target: str) -> dict:
   """Erstellt einen Hardlink.
   
   Args:
       path: Pfad für den neuen Hardlink.
       target: Zieldatei, auf die der Hardlink zeigt.
   """
   abs_path = os.path.abspath(path)
   abs_target = os.path.abspath(target)
   
   if is_path_blocked(abs_path) or is_path_blocked(abs_target):
       return {"error": "Zugriff verweigert für Hardlink oder Ziel"}
   
   try:
       if not os.path.exists(abs_target):
           return {"error": f"Ziel nicht gefunden: {target}"}
       
       if os.path.exists(abs_path) or os.path.islink(abs_path):
           return {"error": f"Hardlink existiert bereits: {path}"}
       
       os.link(abs_target, abs_path)
       
       return {
           "success": True,
           "hardlink": path,
           "target": target,
           "inode": os.stat(abs_path).st_ino,
       }
   except PermissionError:
       return {"error": "Hardlinks erfordern spezielle Berechtigungen auf Windows"}
   except Exception as e:
       return {"error": f"Hardlink-Fehler: {str(e)}"}


@mcp.tool()
def get_recent_files(path: str, max_results: int = 20, time_range_days: int = 7) -> dict:
   """Gibt die zuletzt geänderten Dateien zurück.
   
   Args:
       path: Startverzeichnis für die Suche.
       max_results: Maximale Anzahl Ergebnisse (Default: 20).
       time_range_days: Nur Dateien der letzten N Tage (Default: 7).
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Verzeichnis nicht gefunden: {path}"}
       
       cutoff = time.time() - (time_range_days * 86400)
       recent = []
       
       for root, dirs, files in os.walk(abs_path):
           dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
           for name in files:
               full = os.path.join(root, name)
               try:
                   mtime = os.path.getmtime(full)
                   if mtime >= cutoff:
                       recent.append({
                           "path": os.path.relpath(full, abs_path),
                           "absolute_path": full,
                           "size": os.path.getsize(full),
                           "modified": datetime.fromtimestamp(mtime).isoformat(),
                           "age_days": round((time.time() - mtime) / 86400, 1),
                       })
               except (PermissionError, FileNotFoundError):
                   pass
       
       recent.sort(key=lambda x: x["modified"], reverse=True)  # type: ignore[arg-type]
       recent = recent[:max_results]
       
       return {
           "success": True,
           "path": path,
           "time_range_days": time_range_days,
           "results": recent,
           "count": len(recent),
       }
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_user_directories() -> dict:
   """Gibt die Standard-Benutzerordner zurück (Desktop, Dokumente, Downloads, etc.).
   
   Funktioniert auf Windows, macOS und Linux.
   """
   try:
       home = Path.home()
       result = {"success": True, "home": str(home)}
       
       if IS_WINDOWS:
           import ctypes
           
           folders_map = {
               "Desktop": 0x0010,
               "Documents": 0x0005,
               "Downloads": 0x001E,
               "Music": 0x000B,
               "Pictures": 0x000C,
               "Videos": 0x000E,
               "Favorites": 0x0006,
               "Startup": 0x0007,
               "Programs": 0x0002,
               "AppData_Roaming": 0x001A,
               "AppData_Local": 0x001C,
           }
           
           for folder_name, folder_id in folders_map.items():
               try:
                   path = ctypes.windll.shell32.SHGetFolderPathW(None, folder_id, None, 0)
                   result[folder_name] = path
               except Exception:
                   result[folder_name] = str(home / folder_name.replace("_", "/").replace("AppData_Roaming", "AppData/Roaming").replace("AppData_Local", "AppData/Local"))
       else:
           xdg_dirs = {
               "Desktop": ("XDG_DESKTOP_DIR", "Desktop"),
               "Documents": ("XDG_DOCUMENTS_DIR", "Documents"),
               "Downloads": ("XDG_DOWNLOAD_DIR", "Downloads"),
               "Music": ("XDG_MUSIC_DIR", "Music"),
               "Pictures": ("XDG_PICTURES_DIR", "Pictures"),
               "Videos": ("XDG_VIDEOS_DIR", "Videos"),
           }
           
           for name, default in xdg_dirs.items():
               xdg = os.environ.get(default[0])
               if xdg and os.path.isdir(xdg):
                   result[name] = xdg
               else:
                   result[name] = str(home / default[1])
       
       return result
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def list_drives() -> dict:
   """Gibt alle Laufwerke mit Kapazität zurück.
   
   Auf Windows: alle Laufwerke (C:, D:, etc.)
   Auf Linux/macOS: alle eingehängten Dateisysteme.
   """
   try:
       drives = []
       
       if IS_WINDOWS:
           for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
               path = f"{letter}:\\"
               if os.path.exists(path):
                   try:
                       _, total, free = shutil.disk_usage(path)
                       drives.append({
                           "drive": f"{letter}:",
                           "path": path,
                           "total": f"{total / (1024**3):.2f} GB",
                           "free": f"{free / (1024**3):.2f} GB",
                           "used_percent": round((1 - free / total) * 100, 1) if total > 0 else 0,
                       })
                   except Exception:
                       pass
       else:
           import subprocess
           try:
               result = subprocess.run(["df", "-h"], capture_output=True, text=True)
               for line in result.stdout.splitlines()[1:]:
                   parts = line.split()
                   if len(parts) >= 6:
                       drives.append({
                           "device": parts[0],
                           "mountpoint": parts[5],
                           "size": parts[1],
                           "used": parts[2],
                           "available": parts[3],
                           "use_percent": parts[4],
                       })
           except Exception:
               _, total, free = shutil.disk_usage("/")
               drives.append({
                   "device": "/",
                   "mountpoint": "/",
                   "total": f"{total / (1024**3):.2f} GB",
                   "free": f"{free / (1024**3):.2f} GB",
               })
       
       return {
           "success": True,
           "system": platform.system(),
           "drives": drives,
           "count": len(drives),
       }
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def path_exists(path: str) -> dict:
   """Prüft, ob ein Pfad existiert, und gibt den Typ zurück.
   
   Args:
       path: Zu prüfender Pfad.
   """
   abs_path = os.path.abspath(path)
   
   return {
       "success": True,
       "path": path,
       "absolute_path": abs_path,
       "exists": os.path.exists(abs_path),
       "is_file": os.path.isfile(abs_path),
       "is_directory": os.path.isdir(abs_path),
       "is_symlink": os.path.islink(abs_path),
       "is_absolute": os.path.isabs(path),
   }


@mcp.tool()
def empty_directory(path: str, keep_structure: bool = True) -> dict:
   """Leert ein Verzeichnis (löscht alle Dateien und Unterordner).
   
   Args:
       path: Pfad zum zu leerenden Verzeichnis.
       keep_structure: Wenn True, werden leere Ordnerstrukturen beibehalten.
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Verzeichnis nicht gefunden: {path}"}
       
       if not os.path.isdir(abs_path):
           return {"error": f"Kein Verzeichnis: {path}"}
       
       deleted_files = 0
       deleted_dirs = 0
       
       if keep_structure:
           for root, dirs, files in os.walk(abs_path, topdown=False):
               for f in files:
                   try:
                       os.remove(os.path.join(root, f))
                       deleted_files += 1
                   except Exception:
                       pass
       else:
           for root, dirs, files in os.walk(abs_path, topdown=False):
               for f in files:
                   try:
                       os.remove(os.path.join(root, f))
                       deleted_files += 1
                   except Exception:
                       pass
               for d in dirs:
                   try:
                       os.rmdir(os.path.join(root, d))
                       deleted_dirs += 1
                   except Exception:
                       pass
           os.makedirs(abs_path, exist_ok=True)
       
       return {
           "success": True,
           "path": path,
           "deleted_files": deleted_files,
           "deleted_dirs": deleted_dirs if not keep_structure else 0,
           "keep_structure": keep_structure,
       }
   except PermissionError:
       return {"error": f"Keine Berechtigung: {path}"}
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def move_directory(source: str, destination: str) -> dict:
   """Verschiebt ein gesamtes Verzeichnis.
   
   Args:
       source: Quellverzeichnis.
       destination: Zielverzeichnis.
   """
   abs_src = os.path.abspath(source)
   abs_dst = os.path.abspath(destination)
   
   if is_path_blocked(abs_src) or is_path_blocked(abs_dst):
       return {"error": "Zugriff verweigert für Quelle oder Ziel"}
   
   try:
       if not os.path.exists(abs_src):
           return {"error": f"Quelle nicht gefunden: {source}"}
       
       if not os.path.isdir(abs_src):
           return {"error": f"Quelle ist kein Verzeichnis: {source}"}
       
       shutil.move(abs_src, abs_dst)
       
       return {
           "success": True,
           "source": source,
           "destination": destination,
           "absolute_destination": abs_dst,
       }
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_file_lines(path: str, start: int = 0, end: Optional[int] = None) -> dict:
   """Liest einen Zeilenbereich einer Datei.
   
   Args:
       path: Pfad zur Datei.
       start: Erste Zeile (0-basiert, Default: 0).
       end: Letzte Zeile (exklusiv, None = bis Ende).
   """
   abs_path = os.path.abspath(path)
   if is_path_blocked(abs_path):
       return {"error": f"Zugriff verweigert: {path}"}
   
   try:
       if not os.path.exists(abs_path):
           return {"error": f"Datei nicht gefunden: {path}"}
       
       if os.path.isdir(abs_path):
           return {"error": f"Keine Datei (Verzeichnis): {path}"}
       
       with open(abs_path, "r", encoding="utf-8") as f:
           all_lines = f.readlines()
       
       total_lines = len(all_lines)
       selected = all_lines[start:end]
       
       return {
           "success": True,
           "path": path,
           "total_lines": total_lines,
           "start": start,
           "end": end if end else total_lines,
           "returned_lines": len(selected),
           "content": "".join(selected),
           "lines": [line.rstrip("\n") for line in selected],
       }
   except UnicodeDecodeError:
       return {"error": f"Binärdatei (kann nicht zeilenweise gelesen werden): {path}"}
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


@mcp.tool()
def get_temp_directory() -> dict:
   """Gibt das temporäre Verzeichnis des Systems zurück.
   
   Zeigt auch die Kapazität und den Speicherplatz-Verbrauch an.
   """
   try:
       temp_dir = tempfile.gettempdir()
       abs_temp = os.path.abspath(temp_dir)
       
       temp_files = []
       total_temp_size = 0
       file_count = 0
       dir_count = 0
       
       if os.path.exists(abs_temp):
           for entry in os.scandir(abs_temp):
               try:
                   size = entry.stat().st_size
                   total_temp_size += size
                   if entry.is_file():
                       file_count += 1
                       temp_files.append({
                           "name": entry.name,
                           "size": size,
                           "modified": datetime.fromtimestamp(entry.stat().st_mtime).isoformat(),
                       })
                   else:
                       dir_count += 1
               except Exception:
                   pass
       
       temp_files.sort(key=lambda x: x["size"], reverse=True)  # type: ignore[arg-type]
       
       _, total_bytes, free_bytes = shutil.disk_usage(abs_temp)
       used_bytes = total_bytes - free_bytes
       
       def format_size(size_bytes):
           for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
               if size_bytes < 1024.0:
                   return f"{size_bytes:.2f} {unit}"
               size_bytes /= 1024.0
           return f"{size_bytes:.2f} PB"
       
       return {
           "success": True,
           "temp_directory": temp_dir,
           "absolute_path": abs_temp,
           "system": platform.system(),
           "file_count": file_count,
           "directory_count": dir_count,
           "total_size": format_size(total_temp_size),
           "total_size_bytes": total_temp_size,
           "disk_total": format_size(total_bytes),
           "disk_free": format_size(free_bytes),
           "disk_used_percent": round((used_bytes / total_bytes * 100), 1) if total_bytes > 0 else 0,
           "top_files": temp_files[:10],
       }
   except Exception as e:
       return {"error": f"Fehler: {str(e)}"}


# ============================================================
# Hauptprogramm
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Filesystem Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host (Default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port (Default: 8765)")
    parser.add_argument(
        "--transport",
        default="streamable-http",
        choices=["streamable-http", "sse", "stdio"],
        help="MCP Transport (Default: streamable-http für llama.cpp WebUI)",
    )
    args = parser.parse_args()

    print("[MCP] Filesystem Server starting...", file=sys.stderr)
    print(f"[MCP] Root directory: {DEFAULT_ROOT}", file=sys.stderr)
    print(f"[MCP] OS: {platform.system()} {platform.release()}", file=sys.stderr)
    print(f"[MCP] Python: {platform.python_version()}", file=sys.stderr)
    print(f"[MCP] Transport: {args.transport}", file=sys.stderr)

    if args.transport in ("streamable-http", "sse"):
        # FastMCP gibt uns die rohe Starlette-App, wir packen CORS davor
        # und starten uvicorn selbst -> volle Kontrolle ueber Middleware.
        import uvicorn
        from starlette.middleware.cors import CORSMiddleware
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        if args.transport == "streamable-http":
            app = mcp.streamable_http_app()
            endpoint = "/mcp"
        else:
            app = mcp.sse_app()
            endpoint = "/sse"

        # CORS-Header damit der Browser (llama.cpp WebUI) den Server akzeptiert.
        # MCP nutzt eigene Header (mcp-session-id, mcp-protocol-version) -
        # die müssen exposed werden, sonst kommt der Client nicht weiter.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=False,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            expose_headers=["mcp-session-id", "mcp-protocol-version"],
        )

        # Kleiner Health-Check auf / damit man im Browser checken kann
        # ob der Server lebt (sonst kriegt man da nur 404 und ist verwirrt).
        async def root(_request):
            return JSONResponse({
                "server": SERVER_NAME,
                "transport": args.transport,
                "endpoint": endpoint,
                "hint": f"MCP-URL fuer Clients: http://{args.host}:{args.port}{endpoint}",
            })
        app.routes.append(Route("/", root, methods=["GET"]))

        url = f"http://{args.host}:{args.port}{endpoint}"
        print(f"[MCP] URL: {url}", file=sys.stderr)
        print("[MCP] Trage genau diese URL (mit Pfad!) in der llama.cpp WebUI ein.", file=sys.stderr)

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    else:
        print("[MCP] Waiting for stdio connection...", file=sys.stderr)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[MCP] Server gestoppt (KeyboardInterrupt).", file=sys.stderr)
    except Exception as e:
        print(f"[MCP] FATAL: {type(e).__name__}: {e}", file=sys.stderr)
        raise
