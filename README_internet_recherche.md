# Sichere Internet-Recherche für llama.cpp Web UI

## Übersicht

Dieses Modul bietet **sichere Internet-Recherche-Funktionen** für den MCP-Server, die speziell für die Verwendung mit llama.cpp Web UI entwickelt wurden. Es ermöglicht LLMs, Informationen aus dem Internet zu beziehen, ohne Sicherheitsrisiken einzugehen.

## Verfügbare Quellen

| Quelle | Beschreibung | Tool |
|--------|-------------|------|
| **DuckDuckGo** | Privatsphäre-freundliche Websuche (kein Tracking) | `internet_research`, `safe_web_scrape` |
| **Wikipedia** | Deutsche und englische Wikipedia | `search_wikipedia`, `internet_research` |
| **arXiv** | Wissenschaftliche Paper (Physik, Mathematik, KI, etc.) | `search_arxiv`, `internet_research` |
| **GESTI** | Gefahrstoffdaten der BG BA (Deutschland) | `search_gesti`, `internet_research` |

## Verfügbare Tools

### 1. `internet_research`
Haupttool für allgemeine Internetsuche.

```python
internet_research(
    query="Python Programmierung",
    sources="duckduckgo,wikipedia",
    max_results=5,
    follow_links=False
)
```

### 2. `internet_research_detailed`
Suche mit vollständigen Seiteninhalten (langsamere, aber detailliertere Ergebnisse).

```python
internet_research_detailed(
    query="Quantencomputing Grundlagen",
    sources="wikipedia,duckduckgo",
    max_pages=5
)
```

### 3. `read_webpage`
Liest eine spezifische URL.

```python
read_webpage("https://de.wikipedia.org/wiki/Python")
```

### 4. `search_wikipedia`
Spezialisierte Wikipedia-Suche.

```python
search_wikipedia("Python Programmiersprache", language="de")
```

### 5. `search_arxiv`
Suche nach wissenschaftlichen Paper.

```python
search_arxiv("attention is all you need")
```

### 6. `search_gesti`
Suche nach Gefahrstoffinformationen.

```python
search_gesti("Aceton")
```

### 7. `safe_web_scrape`
Sicheres Scraping beliebiger Webseiten.

```python
safe_web_scrape("https://example.com/article", max_content_length=3000)
```

## Sicherheitsfeatures

### Prompt-Injection-Schutz
- Entfernt potenzielle Prompt-Injection-Muster aus Webseiten-Inhalten
- Blockiert Befehle wie "ignoriere vorherige Anweisungen", "du bist jetzt", etc.
- Entfernt Shell-Befehle und Script-Code aus Inhalten

### URL-Sicherheit
- **Nur http/https** erlaubt
- **Blockierte Domains**: Pastebin, GitHub Gist, Hastebin, etc.
- **Blockierte Endungen**: .exe, .dll, .bat, .ps1, .sh, .py, etc.
- **Keine automatischen Redirects**

### Keine schädlichen Operationen
- **Keine Executables**
- **Keine Downloads**
- **Keine Dateioperationen** (lesen/schreiben/löschen)
- **Keine Netzwerk-Schreibzugriffe** (nur GET-Anfragen)
- **Kein Dateisystem-Zugriff**

### Strikte Limits
- Maximal **15 Seiten** pro Suche
- Maximal **3 Folgelinks** pro Seite
- Maximal **500 KB** Response-Größe
- Maximal **15 Sekunden** Timeout pro Anfrage

## Installation

```bash
pip install duckduckgo-search beautifulsoup4
```

Oder aktualisiere `requirements.txt`:

```
duckduckgo-search>=5.0
beautifulsoup4>=4.12
```

## Verwendung im llama.cpp Web UI

Das Modul wird automatisch in den bestehenden MCP-Server integriert. Starte den Server wie gewohnt:

```bash
python lokales_dateisystem.py --port 8765
```

Die Internet-Recherche-Tools sind dann in der llama.cpp Web UI verfügbar.

## Architektur

```
internet_recherche.py
├── Sicherheits-Utilities
│   ├── is_safe_url()          # URL-Validierung
│   ├── sanitize_html_to_text() # HTML zu Text konvertieren
│   └── sanitize_for_prompt()   # Prompt-Injection-Schutz
│
├── Suchmaschinen
│   ├── DuckDuckGoSearcher
│   ├── WikipediaSearcher
│   ├── ArXivSearcher
│   └── GESTISearcher
│
├── SafeHttpClient
│   └── HTTP-Client mit Limits
│
└── InternetResearchEngine
    ├── search()               # Grundlegende Suche
    ├── search_and_read()      # Suche + Seiteninhalt
    └── read_url()             # Einzelne URL lesen
```

## Beispiel-Ausgabe

```json
{
    "success": true,
    "query": "Python Programmierung",
    "sources_used": ["duckduckgo", "wikipedia"],
    "total_results": 8,
    "pages_scraped": 2,
    "results": [
        {
            "title": "Python (Programmiersprache)",
            "url": "https://de.wikipedia.org/wiki/Python_(Programmiersprache)",
            "snippet": "Python ist eine...",
            "source": "wikipedia(de)"
        },
        {
            "title": "Python Tutorial",
            "url": "https://docs.python.org/3/tutorial/",
            "snippet": "Official Python tutorial...",
            "source": "duckduckgo"
        }
    ],
    "warnings": []
}
```
