@echo off
REM UTF-8 Codepage fuer Umlaute und Emojis
chcp 65001 >nul
setlocal enabledelayedexpansion

REM Python soll stdin/stdout/stderr in UTF-8 nutzen

REM Ins Skript-Verzeichnis wechseln
cd /d "%~dp0"

echo ========================================
echo   MCP Filesystem Server fuer llama.cpp
echo ========================================
echo.

REM ---------- [1/3] Virtual Environment ----------
if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Erstelle virtuelle Umgebung...
    python -m venv .venv
    if errorlevel 1 (
        echo.
        echo FEHLER: venv konnte nicht erstellt werden.
        echo Pruefe ob Python 3.12+ installiert und im PATH ist:
        echo     python --version
        pause
        exit /b 1
    )
) else (
    echo [1/3] Virtuelle Umgebung gefunden.
)

REM ---------- [2/3] venv aktivieren ----------
echo [2/3] Aktiviere virtuelle Umgebung...
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo FEHLER: venv konnte nicht aktiviert werden.
    pause
    exit /b 1
)

REM ---------- [3/3] Abhaengigkeiten ----------
echo [3/3] Installiere Abhaengigkeiten...
python -m pip install --upgrade pip >nul 2>&1
if exist "requirements.txt" (
    python -m pip install -r requirements.txt
) else (
    python -m pip install "mcp[cli]" pywin32
)
if errorlevel 1 (
    echo.
    echo FEHLER: pip install fehlgeschlagen.
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Server wird gestartet (HTTP Transport)
echo ========================================
echo   STRG+C zum Beenden
echo ========================================
echo.

REM Server starten - Standard: streamable-http auf 127.0.0.1:8765
REM URL fuer llama.cpp WebUI: http://127.0.0.1:8765/mcp
python lokales_dateisystem.py --host 127.0.0.1 --port 8765 --transport streamable-http

if errorlevel 1 (
    echo.
    echo ========================================
    echo   Server wurde mit Fehler beendet!
    echo ========================================
    pause
)

endlocal