# MCP Filesystem Server für llama.cpp

Ein Model Context Protocol (MCP) Server, der dem LLM über llama.cpp
Zugriff auf das lokale Windows-Dateisystem ermöglicht.

## Installation

1. Python 3.12+ installieren
2. `run_server.bat` ausführen

## Verfügbare Tools

| Tool            | Beschreibung                          |
|-----------------|---------------------------------------|
| read_file       | Dateiinhalt lesen                     |
| write_file      | Datei schreiben / anhängen            |
| list_directory  | Verzeichnis auflisten                 |
| copy_file       | Datei kopieren                        |
| move_file       | Datei verschieben / umbenennen        |
| delete_file     | Datei/Ordner löschen                  |
| get_file_info   | Dateiinformationen (Größe, Datum)     |
| create_directory| Ordner erstellen                      |
| search_files    | Dateien mit Glob-Muster suchen        |
| get_working_directory | Aktuelles Arbeitsverzeichnis    |

## Sicherheit

- Blockierte Systemverzeichnisse sind gesperrt
- Pfade werden als absolut aufgelöst
