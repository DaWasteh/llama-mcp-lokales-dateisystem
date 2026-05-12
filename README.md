# MCP Filesystem Server für llama.cpp

Ein Model Context Protocol (MCP) Server, der dem LLM über llama.cpp
Zugriff auf das lokale Dateisystem ermöglicht (Windows, Linux, macOS).

## Installation

1. Python 3.12+ installieren
2. Python-Umgebung einrichten:

   ```bat
   python -m venv .venv
   .venv\Scripts\activate.bat
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. `run_server.bat` ausführen oder direkt starten:

    ```bat
    python lokales_dateisystem.py --host 127.0.0.1 --port 8765 --transport streamable-http
    ```

## Verfügbare Tools

### Dateioperationen

| Tool                  | Beschreibung                                          | Parameter                                             |
|-----------------------|-------------------------------------------------------|-------------------------------------------------------|
| read_file             | Dateiinhalt lesen (Text oder Base64 bei Binärdateien) | `path`                                                |
| read_file_binary      | Datei als Base64-codierte Binärdaten lesen            | `path`                                                |
| write_file            | Datei schreiben / anhängen mit Codierung              | `path`, `content`, `append=False`, `encoding="utf-8"` |
| write_file_binary     | Binärdaten (Base64) in Datei schreiben                | `path`, `content`, `encoding="base64"`                |
| rename_file           | Datei oder Verzeichnis umbenennen                     | `path`, `new_name`                                    |
| touch_file            | Zeitstempel aktualisieren oder Datei erstellen        | `path`, `times=None`                                  |
| get_file_lines        | Zeilenbereich lesen (Start/Ende Zeile)                | `path`, `start=0`, `end=None`                         |

### Verzeichnisoperationen

| Tool               | Beschreibung                                      | Parameter                                    |
|--------------------|---------------------------------------------------|----------------------------------------------|
| list_directory     | Verzeichnis auflisten (mit hidden/recursiv)       | `path`, `recursive=False`, `hidden=False`    |
| get_tree           | Verzeichnisbaum mit Einrückung und Emoji-Icons    | `path`, `max_depth=5`, `hidden=False`        |
| create_directory   | Ordner erstellen (mit Eltern-Pfaden)              | `path`, `parents=True`                       |
| delete_file        | Datei/Ordner löschen                              | `path`                                       |
| count_entries      | Anzahl Dateien/Ordner in Verzeichnis zählen       | `path`, `recursive=False`                    |
| empty_directory    | Verzeichnis leeren (Option: Struktur behalten)    | `path`, `keep_structure=True`                |
| move_directory     | Komplettes Verzeichnis verschieben                | `source`, `destination`                      |

### Kopieren & Verschieben

| Tool                | Beschreibung                                   | Parameter                                      |
|---------------------|------------------------------------------------|------------------------------------------------|
| copy_file           | Datei kopieren                                 | `source`, `destination`                        |
| copy_directory      | Verzeichnis rekursiv kopieren                  | `source`, `destination`, `preserve_times=True` |
| move_file           | Datei verschieben / umbenennen                 | `source`, `destination`                        |
| create_hardlink     | Hardlink erstellen                             | `path`, `target`                               |

### Archivoperationen

| Tool                 | Beschreibung                           | Parameter                                         |
|----------------------|----------------------------------------|---------------------------------------------------|
| compress_archive     | Datei/Verzeichnis als ZIP komprimieren | `path`, `archive_path`, `compression="DEFLATED"`  |
| decompress_archive   | ZIP-Archiv entpacken                   | `archive_path`, `destination`                     |

### Suche

| Tool             | Beschreibung                                    | Parameter                                                        |
|------------------|-------------------------------------------------|------------------------------------------------------------------|
| search_files     | Dateien mit Glob-Muster suchen (case-sensitive) | `path`, `pattern="*"`, `max_results=100`, `case_sensitive=False` |
| get_recent_files | Zuletzt geänderte Dateien finden                | `path`, `max_results=20`, `time_range_days=7`                    |

### Informationen

| Tool                 | Beschreibung                                   | Parameter                     |
|----------------------|------------------------------------------------|-------------------------------|
| get_file_info        | Dateiinformationen (Größe, Datum, Typ, Symlink)| `path`                        |
| get_disk_usage       | Festplattenauslastung anzeigen                 | `path="."`                    |
| get_working_directory| Aktuelles Arbeitsverzeichnis und System-Info   | (keine)                       |
| get_allowed_roots    | Konfigurierte Root-Pfade und blockierte Pfade  | (keine)                       |
| get_file_hash        | Hash berechnen (MD5, SHA1, SHA256, SHA512)     | `path`, `algorithm="sha256"`  |
| get_file_permissions | Dateiberechtigungen lesen (Unix-Modus)         | `path`                        |
| chmod_file           | Dateiberechtigungen ändern (chmod)             | `path`, `mode`                |
| list_drives          | Alle Laufwerke mit Kapazität anzeigen          | (keine)                       |
| get_user_directories | Benutzer-Ordner (Desktop, Dokumente, etc.)     | (keine)                       |
| get_temp_directory   | Temp-Verzeichnis mit Speicherplatz-Analyse     | (keine)                       |
| path_exists          | Pfadexistenz und Typ prüfen                    | `path`                        |

### Symlinks

| Tool             | Beschreibung                          | Parameter                              |
|------------------|---------------------------------------|----------------------------------------|
| create_symlink   | Symbolischen Link erstellen           | `path`, `target`, `is_directory=False` |
| resolve_symlink  | Symlink auflösen und Ziel anzeigen    | `path`                                 |

### Internet-Recherche (optional)

| Tool                       | Beschreibung                                     |
|----------------------------|--------------------------------------------------|
| internet_research          | Allgemeine Internetsuche (DuckDuckGo, Wikipedia) |
| internet_research_detailed | Suche mit vollständigen Seiteninhalten           |
| read_webpage               | Spezifische URL lesen                            |
| search_wikipedia           | Spezialisierte Wikipedia-Suche                   |
| search_arxiv               | Wissenschaftliche Paper suchen                   |
| search_gesti               | Gefahrstoffdaten suchen                          |
| safe_web_scrape            | Sicheres Scraping beliebiger Webseiten           |

> **Hinweis:** Internet-Recherche-Tools sind nur verfügbar, wenn `duckduckgo-search` und `beautifulsoup4` installiert sind. Siehe [`README_internet_recherche.md`](README_internet_recherche.md) für Details.

## Sicherheit

- Blockierte Systemverzeichnisse sind gesperrt
- Pfade werden als absolut aufgelöst
- Alle Pfadoperationen werden auf Berechtigung geprüft
- Blockierte Pfade: System32\config, WindowsApps, /etc/shadow, /etc/sudoers

## Konfiguration

Umgebungsvariablen:

- `MCP_FILESYSTEM_ROOT` - Startverzeichnis (Default: Home-Verzeichnis)

## Transport-Modi

| Modus              | Beschreibung                           |
|--------------------|----------------------------------------|
| streamable-http    | HTTP-Transport (empfohlen für WebUI)   |
| sse                | Server-Sent Events                     |
| stdio              | Standard-Ein/Ausgabe (lokale Nutzung)  |

## Hinweis

Der Server nutzt UTF-8-Codierung für Eingabe/Ausgabe. Bei Problemen mit Umlauten bitte sicherstellen, dass die Umgebung Variablen `PYTHONUTF8=1` und `PYTHONIOENCODING=utf-8` gesetzt sind.

## Beispiel-URL

```
http://127.0.0.1:8765/mcp
```
