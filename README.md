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

| Tool                  | Beschreibung                                          |
|-----------------------|-------------------------------------------------------|
| read_file             | Dateiinhalt lesen (Text oder Base64 bei Binärdateien) |
| read_file_binary      | Datei als Base64-codierte Binärdaten lesen            |
| write_file            | Datei schreiben / anhängen mit Codierung              |
| write_file_binary     | Binärdaten (Base64) in Datei schreiben                |
| rename_file           | Datei oder Verzeichnis umbenennen                     |
| touch_file            | Zeitstempel aktualisieren oder Datei erstellen        |
| get_file_lines        | Zeilenbereich lesen (Start/Ende Zeile)                |

### Verzeichnisoperationen

| Tool               | Beschreibung                                      |
|--------------------|---------------------------------------------------|
| list_directory     | Verzeichnis auflisten (mit hidden/recursiv)       |
| get_tree           | Verzeichnisbaum mit Einrückung und Emoji-Icons    |
| create_directory   | Ordner erstellen (mit Eltern-Pfaden)              |
| delete_file        | Datei/Ordner löschen                              |
| count_entries      | Anzahl Dateien/Ordner in Verzeichnis zählen       |
| empty_directory    | Verzeichnis leeren (Option: Struktur behalten)    |
| move_directory     | Komplettes Verzeichnis verschieben                |

### Kopieren & Verschieben

| Tool                | Beschreibung                                   |
|---------------------|------------------------------------------------|
| copy_file           | Datei kopieren                                 |
| copy_directory      | Verzeichnis rekursiv kopieren                  |
| move_file           | Datei verschieben / umbenennen                 |
| create_hardlink     | Hardlink erstellen                            |

### Archivoperationen

| Tool                 | Beschreibung                           |
|----------------------|----------------------------------------|
| compress_archive     | Datei/Verzeichnis als ZIP komprimieren |
| decompress_archive   | ZIP-Archiv entpacken                   |

### Suche

| Tool             | Beschreibung                                    |
|------------------|-------------------------------------------------|
| search_files     | Dateien mit Glob-Muster suchen (case-sensitive) |
| get_recent_files | Zuletzt geänderte Dateien finden                |

### Informationen

| Tool                 | Beschreibung                                   |
|----------------------|------------------------------------------------|
| get_file_info        | Dateiinformationen (Größe, Datum, Typ, Symlink)|
| get_disk_usage       | Festplattenauslastung anzeigen                 |
| get_working_directory| Aktuelles Arbeitsverzeichnis und System-Info   |
| get_allowed_roots    | Konfigurierte Root-Pfade und blockierte Pfade  |
| get_file_hash        | Hash berechnen (MD5, SHA1, SHA256, SHA512)    |
| get_file_permissions | Dateiberechtigungen lesen (Unix-Modus)         |
| chmod_file           | Dateiberechtigungen ändern (chmod)             |
| list_drives          | Alle Laufwerke mit Kapazität anzeigen          |
| get_user_directories | Benutzer-Ordner (Desktop, Dokumente, etc.)     |
| get_temp_directory   | Temp-Verzeichnis mit Speicherplatz-Analyse     |
| path_exists          | Pfadexistenz und Typ prüfen                    |

### Symlinks

| Tool             | Beschreibung                          |
|------------------|---------------------------------------|
| create_symlink   | Symbolischen Link erstellen           |
| resolve_symlink  | Symlink auflösen und Ziel anzeigen    |

### Hardlinks

| Tool            | Beschreibung                         |
|-----------------|--------------------------------------|
| create_hardlink | Hardlink erstellen                   |

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
