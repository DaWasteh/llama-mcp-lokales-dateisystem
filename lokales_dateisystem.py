"""
MCP Server für lokalen Dateisystem-Zugriff (Windows)
Kompatibel mit llama.cpp (getestet mit b9010) WebUI via Streamable HTTP Transport.

Tool-Schemas werden von FastMCP automatisch aus Type Hints + Docstrings
generiert -> kein manuelles inputSchema mehr nötig.
"""

import os
import sys
import io
import shutil
import platform
import fnmatch
import base64
import argparse
from pathlib import Path
from datetime import datetime

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

BLOCKED_PATHS = {
    r"C:\Windows\System32\config",
    r"C:\Program Files\WindowsApps",
}

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
def write_file(path: str, content: str, append: bool = False) -> dict:
    """Schreibt Text in eine Datei.

    Args:
        path: Zielpfad für die Datei.
        content: Inhalt, der geschrieben werden soll.
        append: True um an bestehende Datei anzuhängen, False zum Überschreiben.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        mode = "a" if append else "w"
        with open(abs_path, mode, encoding="utf-8") as f:
            f.write(content)
        return {
            "success": True,
            "path": path,
            "bytes_written": len(content),
            "mode": "append" if append else "write",
        }
    except PermissionError:
        return {"error": f"Keine Berechtigung: {path}"}
    except Exception as e:
        return {"error": f"Fehler beim Schreiben: {str(e)}"}


@mcp.tool()
def list_directory(path: str, recursive: bool = False) -> dict:
    """Listet alle Dateien und Unterverzeichnisse eines Verzeichnisses auf.

    Args:
        path: Pfad zum Verzeichnis.
        recursive: Wenn True, werden auch Unterverzeichnisse rekursiv durchsucht.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        entries = []

        if recursive:
            for root, dirs, files in os.walk(abs_path):
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
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        }
    except FileNotFoundError:
        return {"error": f"Nicht gefunden: {path}"}
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


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
def search_files(path: str, pattern: str = "*", max_results: int = 100) -> dict:
    """Durchsucht Dateien rekursiv mit einem Glob-Muster.

    Args:
        path: Startverzeichnis für die Suche.
        pattern: Glob-Muster, z.B. '*.txt' oder 'config*'.
        max_results: Maximale Anzahl Ergebnisse.
    """
    abs_path = os.path.abspath(path)
    if is_path_blocked(abs_path):
        return {"error": f"Zugriff verweigert: {path}"}

    try:
        results = []
        for root, dirs, files in os.walk(abs_path):
            dirs[:] = [d for d in dirs if not is_path_blocked(os.path.join(root, d))]
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    full = os.path.join(root, name)
                    try:
                        results.append({
                            "path": os.path.relpath(full, abs_path),
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
            "results": results,
            "count": len(results),
        }
    except Exception as e:
        return {"error": f"Fehler: {str(e)}"}


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