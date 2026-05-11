"""
Sicherer Internet-Recherche MCP-Server fuer llama.cpp Web UI.

Erlaubte Quellen: DuckDuckGo, Wikipedia, arXiv, GESTI (BG BA)
Sicherheitsfeatures:
- Keine Executables, Downloads, Dateisystem-Zugriff
- Prompt-Injection-Schutz durch Content-Sanitization
- Strikte Limits (Max Tiefe, Max Seiten, Max Token)
- Nur HTTP GET, keine POST/PUT/DELETE
- Blockierte Domains und URL-Schemata

Kann als eigenständiger Server ODER als Modul in bestehenden Server verwendet werden.
"""

import html
import logging
import re
import socket
import sys
import threading
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from time import time
from urllib.parse import quote_plus, urljoin, urlparse

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"FEHLER: MCP SDK nicht installiert. ({e})", file=sys.stderr)
    raise

try:
    import httpx
    from bs4 import BeautifulSoup
    from duckduckgo_search import DDGS
except ImportError as e:
    print(f"FEHLER: Fehlende Abhaengigkeit: {e}", file=sys.stderr)
    raise


# ============================================================
# Logger
# ============================================================
logger = logging.getLogger("internet_recherche")


# ============================================================
# Konfiguration & Sicherheitslimits
# ============================================================

MAX_PAGES_PER_SEARCH = 15
MAX_FOLLOW_LINKS = 3
MAX_RESULT_LENGTH = 5000
MAX_SEARCH_RESULTS = 5
HTTP_TIMEOUT = 15
MAX_RESPONSE_SIZE = 500_000  # 500 KB
REQUESTS_PER_WINDOW = 10  # Rate Limiting: Max Anfragen pro Zeitfenster
WINDOW_SECONDS = 60  # Rate Limiting: Zeitfenster in Sekunden

ALLOWED_SCHEMAS = {"http", "https"}

# Geschuetzte IP-Netze (SSRF-Schutz)
_PROTECTED_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("0.0.0.0/8"),
    ip_network("100.64.0.0/10"),
    ip_network("::1/128"),  # IPv6 Loopback
    ip_network("fc00::/7"),  # IPv6 Unique Local
    ip_network("fe80::/10"),  # IPv6 Link-Local
]

# Blockierte Domains (bekannte Quellen fuer Malware/Prompt-Injection)
BLOCKED_DOMAINS = {
    "pastebin.com",
    "gist.github.com",
    "hastebin.com",
    "paste.ee",
    "0bin.net",
    "dpaste.com",
    "termbin.com",
    "0x0.st",
    "transfer.sh",
    "file.io",
    "temp.sh",
    "raw.githubusercontent.com",
    "huggingface.co",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "jsdelivr.net",
}

# Blockierte Domain-Suffixes (internes Netzwerk)
BLOCKED_DOMAIN_SUFFIXES = (".internal", ".local", ".private", ".corp", ".home", ".lan")

# Blockierte URL-Endungen (Downloads/Executables)
BLOCKED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".sh",
    ".bash",
    ".zsh",
    ".com",
    ".scr",
    ".pif",
    ".vbs",
    ".js",
    ".jar",
    ".app",
    ".dmg",
    ".iso",
    ".img",
    ".py",
    ".pl",
    ".rb",
    ".php",
    ".bin",
    ".elf",
    ".out",
}


def _is_ip_address(hostname: str) -> bool:
    """Prueft, ob der Hostname eine IP-Adresse ist."""
    if ":" in hostname:
        return True
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) is not None


def _is_protected_ip(hostname: str) -> bool:
    """Prueft, ob die IP-Adresse geschuetzt/privat ist."""
    try:
        addr = ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return True
        return any(addr in network for network in _PROTECTED_NETWORKS)
    except ValueError:
        return False


def is_private_ip(hostname: str) -> bool:
    """Prueft, ob hostname eine private IP-Adresse ist (IPv4 und IPv6)."""
    if not hostname:
        return False
    try:
        if ":" in hostname:
            addr = ip_address(hostname)
            return addr.is_private
        addr = ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        return any(addr in network for network in _PROTECTED_NETWORKS)
    except ValueError:
        return False


def resolve_and_verify(hostname: str) -> bool:
    """
    Prueft, ob DNS auf eine private IP auflauft (SSRF-Schutz).

    Returns:
        True wenn die Domain auf eine oeffentliche IP auflauft,
        False wenn sie auf eine private IP auflauft oder der Auflauf fehlschlaegt.
    """
    if not hostname:
        return False
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for info in addr_info:
            ip_raw = info[4][0]
            ip_str = str(ip_raw)
            if is_private_ip(ip_str):
                return False
        return True
    except socket.gaierror:
        return False
    except socket.herror:
        return False
    except OSError:
        return False


def is_safe_url(url: str) -> bool:
    """Prueft, ob eine URL sicher ist."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMAS:
            return False
        if not parsed.hostname:
            return False

        hostname = parsed.hostname.lower().rstrip(".")

        # Blockiere javascript:, data:, file: URLs
        if parsed.scheme in ("javascript", "data", "file"):
            return False

        # Blockiere localhost und bekannte interne Hostnames
        if hostname in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
            return False

        # Blockiere IP-Adressen
        if _is_ip_address(hostname) and is_private_ip(hostname):
            return False

        # Blockiere blockierte Domains und Subdomains
        for blocked in BLOCKED_DOMAINS:
            if hostname == blocked or hostname.endswith("." + blocked):
                return False

        # Blockiere interne Domain-Suffixes
        if hostname.endswith(BLOCKED_DOMAIN_SUFFIXES):
            return False

        # Path-Pruefung
        path_lower = parsed.path.lower()
        return all(not path_lower.endswith(ext) for ext in BLOCKED_EXTENSIONS)
    except Exception:
        return False

ALLOWED_SOURCES = {"duckduckgo", "wikipedia", "arxiv", "gesti"}


# ============================================================
# Datenklassen
# ============================================================


@dataclass
class SearchResult:
    """Ein einzelnes Suchergebnis."""

    title: str
    url: str
    snippet: str
    source: str


@dataclass
class ScrapedPage:
    """Eine gescrapte Webseite."""

    url: str
    title: str
    content: str
    links: list[str]
    source: str


# ============================================================
# Sicherheits-Utilities
# ============================================================


def sanitize_html_to_text(html_content: str, max_length: int = MAX_RESULT_LENGTH) -> str:
    """Konvertiert HTML zu sicherem Text ohne Script/Style-Inhalte."""
    try:
        soup = BeautifulSoup(html_content, "html.parser")

        for tag in soup.find_all(
            [
                "script",
                "style",
                "noscript",
                "iframe",
                "object",
                "embed",
                "form",
                "input",
                "textarea",
                "button",
                "link",
                "meta",
                "base",
            ]
        ):
            tag.decompose()

        for tag in soup.find_all(True):
            tag.attrs = {}

        text = soup.get_text(separator="\n", strip=True)
        text = re.sub(r"\n{3,}", "\n\n", text)

        if len(text) > max_length:
            text = text[:max_length] + "\n... [gekuerzt]"

        return text
    except Exception as e:
        return f"[Fehler bei der HTML-Parsung: {e}]"


class RateLimiter:
    """Einfaches Rate-Limiting pro Session."""

    def __init__(self, max_requests: int = REQUESTS_PER_WINDOW, window_seconds: int = WINDOW_SECONDS):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Prueft, ob eine Anfrage erlaubt ist."""
        now = time()
        with self._lock:
            # Entferne alte Eintraege
            while self.requests and self.requests[0] < now - self.window_seconds:
                self.requests.popleft()

            if len(self.requests) >= self.max_requests:
                return False

            self.requests.append(now)
            return True


def sanitize_for_prompt(text: str) -> str:
    """Sanitisieren fuer sichere Weitergabe an LLM-Prompt."""
    if not text:
        return ""

    text = html.unescape(text)
    text = text.replace("\\n", "\n").replace("\\t", "\t")

    # ERWEITERT: Umfassende Injection-Patterns (30+ Pattern)
    injection_patterns = [
        # Direkte Anweisungen
        r"(?i)ignore\s+all\s+instructions",
        r"(?i)disregard\s+(previous|all|the\s+above)",
        r"(?i)you\s+are\s+now",
        r"(?i)from\s+now\s+on",
        r"(?i)change\s+your\s+(behavior|rules|instructions|prompt)",
        r"(?i)reset\s+(your\s+)?(instructions|prompt|system)",

        # System-Prompt Extraktion
        r"(?i)system\s*[:\-]\s*",
        r"(?i)show\s+your\s+(system\s+)?prompt",
        r"(?i)reveal\s+your\s+instructions",
        r"(?i)previous\s+prompt",
        r"(?i)above\s+instructions",
        r"(?i)display\s+your\s+system",

        # Code Execution
        r"(?i)exec\s*\(",
        r"(?i)eval\s*\(",
        r"(?i)os\.system",
        r"(?i)subprocess\.",
        r"(?i)rm\s+-rf",
        r"(?i)wget\s+.*\|",
        r"(?i)curl\s+.*\|",
        r"(?i)python\s+-c",
        r"(?i)bash\s+-c",
        r"(?i)chmod\s+[0-7]{3,4}",
        r"(?i)nc\s+-[el]",
        r"(?i)mkfifo",
        r"(?i)ncat",

        # Format-Injection
        r"```(?:shell|bash|cmd|powershell|python)\s*\n",
        r"<system\s*>",
        r"<role\s*>",
        r"<\|begin_of_message\|>",
        r"<\|end_of_message\|>",
        r"<\|start_of_content\|>",

        # Base64 und Encoding
        r"(?i)base64\s*(decode|encode)",
        r"[A-Za-z0-9+/]{100,}={0,2}",

        # Chain-of-Thought Manipulation
        r"(?i)let\s+me\s+think\s+step\s*[- ]\s*by\s*[- ]\s*step",
        r"(?i)here\s+is\s+my\s+(full|complete)\s+response",
        r"(?i)think\s+silently",

        # Daten-Exfiltration
        r"(?i)send\s+this\s+to",
        r"(?i)exfiltrat",
        r"(?i)steal\s+your\s+",
        r"(?i)extract\s+your\s+",

        # Rolle-Überschreibung
        r"(?i)you\s+are\s+now\s+a",
        r"(?i)assume\s+the\s+role\s+of",
        r"(?i)act\s+as\s+if",
        r"(?i)adopt\s+the\s+persona\s+of",
    ]

    for pattern in injection_patterns:
        text = re.sub(pattern, "[ENTFERNT: Potenzielle Prompt-Injection]", text)

    text = html.escape(text)
    return text


def is_safe_link(link: str, current_domain: str) -> bool:
    """Prueft, ob ein Link sicher zum Folgen ist."""
    if not is_safe_url(link):
        return False

    parsed = urlparse(link)
    hostname = parsed.hostname or ""

    if parsed.scheme not in ALLOWED_SCHEMAS:
        return False

    return hostname != current_domain


# ============================================================
# HTTP-Client mit Sicherheitslimits
# ============================================================


class SafeHttpClient:
    """Sicherer HTTP-Client mit Limits."""

    def __init__(self, timeout: int = HTTP_TIMEOUT):
        self.timeout = timeout
        self.session = httpx.Client(
            timeout=self.timeout,
            follow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (SafeResearchBot/1.0; +https://safe-research.local)"},
        )

    @staticmethod
    def _sanitize_url_for_logging(url: str) -> str:
        """Extrahiert sichere Teile der URL fuer das Logging."""
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.hostname}{parsed.path}"
        except Exception:
            return "[URL konnte nicht analysiert werden]"

    def fetch(self, url: str, max_size: int = MAX_RESPONSE_SIZE) -> str | None:
        """Sichert eine URL mit Groessenlimit."""
        if not is_safe_url(url):
            safe_url = self._sanitize_url_for_logging(url)
            logger.warning(f"Blockierte unsichere URL: {safe_url}")
            return None

        try:
            response = self.session.get(url)

            if len(response.content) > max_size:
                logger.warning(f"Response zu gross: {len(response.content)} bytes")
                return None

            content_type = response.headers.get("content-type", "").lower()
            if "text/html" not in content_type and "text/plain" not in content_type:
                logger.warning(f"Nicht-HTML Content-Type: {content_type}")
                return None

            return response.text
        except httpx.TimeoutException:
            safe_url = self._sanitize_url_for_logging(url)
            logger.warning(f"Timeout bei {safe_url}")
            return None
        except httpx.InvalidURL:
            safe_url = self._sanitize_url_for_logging(url)
            logger.warning(f"Ungültige URL: {safe_url}")
            return None
        except httpx.TooManyRedirects:
            safe_url = self._sanitize_url_for_logging(url)
            logger.warning(f"Zu viele Redirects: {safe_url}")
            return None
        except Exception:
            safe_url = self._sanitize_url_for_logging(url)
            logger.warning(f"Fehler bei {safe_url}: [interner Fehler]")
            return None

    def close(self):
        self.session.close()


# ============================================================
# Suchmaschinen-Implementierungen
# ============================================================


class DuckDuckGoSearcher:
    """DuckDuckGo Suchmaschine (privatsphare-freundlich, kein Tracking)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        try:
            results = []
            ddgs = DDGS()

            for result in ddgs.text(query, max_results=max_results):
                title = result.get("title", "")
                url = result.get("href", "")
                snippet = result.get("body", "")

                if url and is_safe_url(url):
                    results.append(SearchResult(title=title, url=url, snippet=snippet, source="duckduckgo"))

            return results
        except Exception as e:
            logger.error(f"DuckDuckGo-Fehler: {e}")
            return []


class WikipediaSearcher:
    """Wikipedia-Suchmaschine."""

    WIKI_API_URL = "https://{lang}.wikipedia.org/w/api.php"

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results: list[SearchResult] = []

        for lang in ["de", "en"]:
            if len(results) >= max_results:
                break

            try:
                api_url = self.WIKI_API_URL.format(lang=lang)
                params: Mapping[str, str | int | float | bool | None] = {
                    "action": "query",
                    "list": "search",
                    "srsearch": query,
                    "srlimit": min(max_results - len(results), 5),
                    "format": "json",
                    "srprop": "snippet|title|wordcount",
                    "srinfo": "suggestion",
                }

                with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                    response = client.get(api_url, params=params)  # type: ignore[arg-type]
                    data = response.json()

                    search_terms = data.get("query", {}).get("search", [])

                    for term in search_terms:
                        title = term.get("title", "")
                        snippet = term.get("snippet", "")

                        article_url = f"https://{lang}.wikipedia.org/wiki/{quote_plus(title)}"

                        results.append(
                            SearchResult(
                                title=title,
                                url=article_url,
                                snippet=self._clean_wikipedia_snippet(snippet),
                                source=f"wikipedia({lang})",
                            )
                        )

                        if len(results) >= max_results:
                            break

            except Exception as e:
                logger.error(f"Wikipedia({lang})-Fehler: {e}")
                continue

        return results[:max_results]

    def _clean_wikipedia_snippet(self, snippet: str) -> str:
        """Wikipedia-Snippet bereinigen."""
        if not snippet:
            return ""
        snippet = html.unescape(snippet)
        snippet = re.sub(r"\[\d+\]", "", snippet)
        return snippet.strip()

    def get_article(self, url: str) -> ScrapedPage | None:
        """Wikipedia-Artikel abrufen."""
        try:
            parsed = urlparse(url)
            parts = parsed.path.strip("/").split("/", 1)
            lang = parts[0] if parts else "en"
            title = parts[1] if len(parts) > 1 else ""

            api_url = self.WIKI_API_URL.format(lang=lang)
            params: Mapping[str, str | int | float | bool | None] = {
                "action": "query",
                "titles": title,
                "prop": "extracts|info",
                "inprop": "url",
                "explaintext": True,
                "format": "json",
            }

            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                response = client.get(api_url, params=params)  # type: ignore[arg-type]
                data = response.json()

                pages = data.get("query", {}).get("pages", {})
                for _page_id, page_data in pages.items():
                    if page_data.get("missing"):
                        return None

                    article_title = page_data.get("title", "")
                    extract = page_data.get("extract", "")

                    if extract:
                        sanitized = sanitize_for_prompt(extract)
                        return ScrapedPage(
                            url=url, title=article_title, content=sanitized, links=[], source=f"wikipedia({lang})"
                        )

            return None

        except Exception as e:
            logger.error(f"Wikipedia-Artikel-Fehler: {e}")
            return None


class ArXivSearcher:
    """arXiv-Suchmaschine fuer wissenschaftliche Paper."""

    ARXIV_API = "http://export.arxiv.org/api/query"

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results = []

        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                response = client.get(
                    self.ARXIV_API,
                    params={
                        "query": f"all:{query}",
                        "start": 0,
                        "max_results": min(max_results, 10),
                        "sortBy": "relevance",
                        "sortOrder": "descending",
                    },
                )

                from xml.etree import ElementTree

                root = ElementTree.fromstring(response.content)

                namespace = {
                    "atom": "http://www.w3.org/2005/Atom",
                    "opensearch": "http://a9.com/-/spec/opensearch/1.1/",
                }

                for entry in root.findall(".//atom:entry", namespace):
                    title = entry.findtext("atom:title", "").strip().replace("\n", " ")
                    summary = entry.findtext("atom:summary", "").strip().replace("\n", " ")
                    link = entry.findtext("atom:link", "")

                    abstract_url = ""
                    for link_elem in entry.findall("atom:link", namespace):
                        href = link_elem.get("href", "")
                        if "abs" in href.lower() or "entry" in href.lower():
                            abstract_url = href

                    if not abstract_url:
                        abstract_url = link

                    if abstract_url:
                        results.append(
                            SearchResult(
                                title=title, url=abstract_url, snippet=self._clean_arxiv_text(summary), source="arxiv"
                            )
                        )

        except Exception as e:
            logger.error(f"arXiv-Fehler: {e}")

        return results[:max_results]

    def _clean_arxiv_text(self, text: str) -> str:
        """arXiv-Text bereinigen."""
        if not text:
            return ""
        text = text.replace("&lt;", "<").replace("&gt;", ">")
        text = text.replace("&amp;", "&").replace("&quot;", '"')
        text = text.replace("&apos;", "'")
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def get_paper_details(self, url: str) -> ScrapedPage | None:
        """arXiv-Paper-Details abrufen."""
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                arxiv_id = urlsplit_id(url)
                if not arxiv_id:
                    return None

                response = client.get(
                    self.ARXIV_API,
                    params={
                        "search_query": f"id:{arxiv_id}",
                        "max_results": 1,
                    },
                )

                from xml.etree import ElementTree

                root = ElementTree.fromstring(response.content)
                namespace = {"atom": "http://www.w3.org/2005/Atom"}

                for entry in root.findall(".//atom:entry", namespace):
                    title = entry.findtext("atom:title", "").strip().replace("\n", " ")
                    summary = entry.findtext("atom:summary", "").strip().replace("\n", " ")

                    authors = []
                    for author in entry.findall("atom:author", namespace):
                        name = author.findtext("atom:name", "")
                        if name:
                            authors.append(name)

                    if summary:
                        content = f"Titel: {title}\nAutoren: {', '.join(authors)}\n\nZusammenfassung:\n{self._clean_arxiv_text(summary)}"
                        sanitized = sanitize_for_prompt(content)

                        return ScrapedPage(url=url, title=title, content=sanitized, links=[], source="arxiv")

            return None

        except Exception as e:
            logger.error(f"arXiv-Paper-Fehler: {e}")
            return None


def urlsplit_id(url: str) -> str:
    """arXiv-ID aus URL extrahieren."""
    try:
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        parts = path.split("/")
        for part in parts:
            if re.match(r"\d{4}\.\d{4,5}(v\d+)?", part):
                return part.split("v")[0]
        return parts[-1] if parts else ""
    except Exception:
        return ""


class GESTISearcher:
    """GESTI-Suche der BG BA (Gefahrdungsbeurteilung, Stoffdaten)."""

    def search(self, query: str, max_results: int = MAX_SEARCH_RESULTS) -> list[SearchResult]:
        results = []

        try:
            ddgs = DDGS()
            for result in ddgs.text(f"site:gesti.bgba.de {query}", max_results=max_results):
                url = result.get("href", "")
                if "gesti.bgba.de" in url:
                    results.append(
                        SearchResult(
                            title=result.get("title", ""), url=url, snippet=result.get("body", ""), source="gesti"
                        )
                    )

        except Exception as e:
            logger.error(f"GESTI-Fehler: {e}")

        return results


# ============================================================
# Haupt-Recherche-Engine
# ============================================================


class InternetResearchEngine:
    """Haupt-Engine fuer sichere Internet-Recherche."""

    def __init__(self):
        self.http_client = SafeHttpClient()
        self.ddg = DuckDuckGoSearcher()
        self.wiki = WikipediaSearcher()
        self.arxiv = ArXivSearcher()
        self.gesti = GESTISearcher()
        self._visited_urls: set[str] = set()
        self._page_count = 0

    def _dummy_for_mypy(self) -> None:
        """Dummy-Methode, um MyPy-Prüfung fuer __init__ zu aktivieren."""
        pass

    def reset(self):
        """Suche zuruecksetzen."""
        self._visited_urls.clear()
        self._page_count = 0

    def search(
        self,
        query: str,
        sources: list[str] | None = None,
        max_results: int = MAX_SEARCH_RESULTS,
        follow_links: bool = False,
        max_follow_links: int = MAX_FOLLOW_LINKS,
    ) -> dict:
        """Fuehrt eine sichere Internet-Recherche durch."""
        if sources is None:
            sources = ["duckduckgo", "wikipedia"]

        sources = [s.lower() for s in sources if s.lower() in ALLOWED_SOURCES]
        if not sources:
            sources = ["duckduckgo", "wikipedia"]

        self.reset()

        all_results: list[dict] = []
        total_pages = 0

        try:
            if "duckduckgo" in sources:
                for r in self.ddg.search(query, max_results):
                    all_results.append(
                        {
                            "title": r.title,
                            "url": r.url,
                            "snippet": sanitize_for_prompt(r.snippet),
                            "source": r.source,
                        }
                    )
                    total_pages += 1

            if "wikipedia" in sources:
                for r in self.wiki.search(query, max_results):
                    all_results.append(
                        {
                            "title": r.title,
                            "url": r.url,
                            "snippet": sanitize_for_prompt(r.snippet),
                            "source": r.source,
                        }
                    )
                    total_pages += 1

            if "arxiv" in sources:
                for r in self.arxiv.search(query, max_results):
                    all_results.append(
                        {
                            "title": r.title,
                            "url": r.url,
                            "snippet": sanitize_for_prompt(r.snippet),
                            "source": r.source,
                        }
                    )
                    total_pages += 1

            if "gesti" in sources:
                for r in self.gesti.search(query, max_results):
                    all_results.append(
                        {
                            "title": r.title,
                            "url": r.url,
                            "snippet": sanitize_for_prompt(r.snippet),
                            "source": r.source,
                        }
                    )
                    total_pages += 1

            if follow_links and max_follow_links > 0:
                all_results, total_pages = self._follow_links(all_results, max_follow_links, max_results * 3)

            all_results = all_results[: max_results * 3]

            return {
                "success": True,
                "query": query,
                "sources_used": sources,
                "total_results": len(all_results),
                "pages_scraped": total_pages,
                "results": all_results,
                "warnings": self._generate_warnings(total_pages),
            }

        finally:
            self.reset()

    def search_and_read(
        self,
        query: str,
        sources: list[str] | None = None,
        max_pages: int = MAX_PAGES_PER_SEARCH,
    ) -> dict:
        """Suche und lese vollständige Seiteninhalte."""
        if sources is None:
            sources = ["duckduckgo", "wikipedia"]

        self.reset()
        self._page_count = 0

        try:
            search_results = self.search(query, sources, max_pages)

            if not search_results.get("success"):
                return search_results

            detailed_results = []
            for result in search_results["results"][:max_pages]:
                if self._page_count >= max_pages:
                    break

                page = self._read_page(result["url"], result.get("source", ""))
                if page:
                    detailed_results.append(page)
                    self._page_count += 1

            search_results["detailed_pages"] = detailed_results
            search_results["pages_read"] = self._page_count

            return search_results

        finally:
            self.reset()

    def read_url(self, url: str) -> dict:
        """Liest eine spezifische URL sicher."""
        self.reset()

        try:
            page = self._read_page(url, "")
            if page:
                return {
                    "success": True,
                    "url": url,
                    "title": page.title,
                    "content": page.content,
                    "source": page.source,
                }
            else:
                return {
                    "success": False,
                    "url": url,
                    "error": "Seite konnte nicht gelesen werden",
                }
        finally:
            self.reset()

    def _read_page(self, url: str, source_hint: str) -> ScrapedPage | None:
        """Seite sicher lesen."""
        if not is_safe_url(url):
            logger.warning(f"Blockierte URL: {url}")
            return None

        if url in self._visited_urls:
            logger.warning(f"Bereits besucht: {url}")
            return None

        if self._page_count >= MAX_PAGES_PER_SEARCH:
            logger.warning("Maximale Seitenanzahl erreicht")
            return None

        self._visited_urls.add(url)
        self._page_count += 1

        if "wikipedia.org" in url:
            return self.wiki.get_article(url)

        if "arxiv.org" in url:
            arxiv_id = urlsplit_id(url)
            if arxiv_id:
                page = self.arxiv.get_paper_details(url)
                if page:
                    return page

        html_content = self.http_client.fetch(url)
        if not html_content:
            return None

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            title = soup.find("title")
            title_text = title.get_text(strip=True) if title else urlparse(url).hostname or "Ohne Titel"

            content = sanitize_html_to_text(html_content)

            current_domain = urlparse(url).hostname or ""
            links: list[str] = []
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag.get("href", ""))
                full_url = str(urljoin(url, href))
                if is_safe_link(full_url, current_domain):
                    links.append(full_url)
                    if len(links) >= MAX_FOLLOW_LINKS:
                        break

            return ScrapedPage(
                url=url,
                title=title_text,
                content=content,
                links=links,
                source=source_hint or "web",
            )

        except Exception as e:
            logger.error(f"Fehler beim Parsen von {url}: {e}")
            return None

    def _follow_links(
        self,
        results: list[dict],
        max_follow: int,
        total_limit: int,
    ) -> tuple:
        """Folgt sicheren Links in den Suchergebnissen."""
        new_results = []
        page_count = 0

        for result in results:
            if page_count >= total_limit:
                break

            url = result.get("url", "")
            if not is_safe_url(url):
                continue

            if result.get("source") in ("duckduckgo",):
                page = self._read_page(url, "web")
                if page:
                    page_count += 1
                    new_results.append(
                        {
                            "title": page.title,
                            "url": page.url,
                            "snippet": page.content[:500],
                            "source": page.source,
                            "followed_from": result.get("url"),
                        }
                    )

                    if len(new_results) >= max_follow:
                        break

        return results + new_results, page_count

    def _generate_warnings(self, page_count: int) -> list[str]:
        """Generiert Warnungen bei Limits."""
        warnings = []
        if page_count >= MAX_PAGES_PER_SEARCH:
            warnings.append(f"Maximale Seitenanzahl ({MAX_PAGES_PER_SEARCH}) erreicht")
        if page_count >= MAX_PAGES_PER_SEARCH * 0.8:
            warnings.append("Nahe am Limit - Ergebnisse koennten unvollstaendig sein")
        return warnings

    def close(self):
        self.http_client.close()


# ============================================================
# Thread-lokale Engine-Instanz (Thread-Safety)
# ============================================================

_local = threading.local()


def get_engine() -> InternetResearchEngine:
    """Gibt eine thread-lokale Engine-Instanz zurueck."""
    if not hasattr(_local, "engine") or _local.engine is None:
        _local.engine = InternetResearchEngine()
    engine_instance: InternetResearchEngine = _local.engine  # type: ignore[assignment]
    return engine_instance


# Beibehaltung von `engine` als Kompatibilitaets-Alias (aber nicht mehr empfohlen)
engine = get_engine()


# ============================================================
# Reine Funktionen (ohne MCP-Decorator)
# ============================================================
# Diese Funktionen koennen mit JEDEM FastMCP-Server verwendet werden.
# Sie werden im Hauptserver als @mcp.tool() registriert.


def _make_internet_research(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der research-Funktion."""

    def internet_research(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_results: int = 5,
        follow_links: bool = False,
    ) -> dict:
        """
        Sichere Internet-Recherche mit mehreren Quellen.

        Durchsucht das Internet sicher nach Informationen. Nur Lesezugriff,
        keine Dateioperationen oder Executables.

        Features:
        - Prompt-Injection-Schutz (schaedliche Inhalte werden entfernt)
        - Blockierte Domains und Download-Endungen
        - Strikte Limits (Max Seiten, Max Token)
        - Keine Netzwerk-Schreibzugriffe

        Args:
            query: Suchbegriff oder Frage
            sources: Komma-getrennte Liste der Quellen:
                     - duckduckgo: Websuche (privatsphare-freundlich)
                     - wikipedia: Wikipedia (DE/EN)
                     - arxiv: Wissenschaftliche Paper
                     - gesti: GESTI Gefahrstoffe (BG BA)
            max_results: Maximale Anzahl der Suchergebnisse (1-15)
            follow_links: True um bis zu 3 Folgelinks pro Seite zu folgen

        Returns:
            Dict mit Suchergebnissen, Titeln, URLs und Snippets

        Beispiele:
            >>> internet_research("Python Programmierung", sources="wikipedia,duckduckgo")
            >>> internet_research("transformer attention mechanism", sources="arxiv")
            >>> internet_research("Blei Gefahrstoffe", sources="gesti,duckduckgo")
        """
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_results = max(1, min(max_results, MAX_SEARCH_RESULTS))

            result = engine.search(
                query=query,
                sources=source_list,
                max_results=max_results,
                follow_links=follow_links,
            )
            return result

        except Exception as e:
            logger.error(f"internet_research interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "query": query,
                "results": [],
            }

    return internet_research


def _make_internet_research_detailed(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der detailed research-Funktion."""

    def internet_research_detailed(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_pages: int = 5,
    ) -> dict:
        """
        Sichere Internet-Recherche mit vollständigen Seiteninhalten.

        Sucht nach Informationen und liest die Top-Ergebnisse vollständig aus.
        Langsamere, aber detailliertere Ergebnisse als internet_research.

        Args:
            query: Suchbegriff oder Frage
            sources: Komma-getrennte Quellen (siehe internet_research)
            max_pages: Maximale Anzahl vollständig gelesener Seiten (1-10)

        Returns:
            Dict mit Suchergebnissen und vollständigen Seiteninhalten

        Beispiele:
            >>> internet_research_detailed("Quantencomputing Grundlagen")
            >>> internet_research_detailed("Maschinelles Lernen Tutorial", sources="wikipedia")
        """
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_pages = max(1, min(max_pages, 10))

            result = engine.search_and_read(
                query=query,
                sources=source_list,
                max_pages=max_pages,
            )
            return result

        except Exception as e:
            logger.error(f"internet_research_detailed interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "query": query,
                "results": [],
                "detailed_pages": [],
            }

    return internet_research_detailed


def _make_read_webpage(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der read_webpage-Funktion."""

    def read_webpage(url: str) -> dict:
        """
        Liest eine spezifische Webseite sicher.

        Extrahiert den Textinhalt einer Webseite und entfernt alle
        Skripte, Styles und potenziell schaedliche Inhalte.

        ACHTUNG: Nur http/https, keine Dateioperationen moeglich.

        Args:
            url: Vollstaendige URL der zu lesenden Webseite

        Returns:
            Dict mit Titel, Inhalt und URL der Seite

        Beispiele:
            >>> read_webpage("https://de.wikipedia.org/wiki/Python")
            >>> read_webpage("https://arxiv.org/abs/2301.12345")
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return {
                    "success": False,
                    "error": "Ungültige URL",
                    "url": url,
                }

            if not is_safe_url(url):
                return {
                    "success": False,
                    "error": f"URL blockiert: {url}",
                    "url": url,
                }

            result = engine.read_url(url)
            return result

        except Exception as e:
            logger.error(f"read_webpage interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "url": url,
            }

    return read_webpage


def _make_search_wikipedia(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der search_wikipedia-Funktion."""

    def search_wikipedia(query: str, language: str = "de") -> dict:
        """
        Durchsucht Wikipedia.

        Sucht in der deutschen oder englischen Wikipedia.

        Args:
            query: Suchbegriff
            language: "de" für Deutsch, "en" für Englisch

        Returns:
            Dict mit Wikipedia-Suchergebnissen

        Beispiele:
            >>> search_wikipedia("Python Programmiersprache")
            >>> search_wikipedia("Machine Learning", language="en")
        """
        try:
            if language not in ("de", "en"):
                language = "de"

            results = WikipediaSearcher().search(query, max_results=5)

            formatted = []
            for r in results:
                formatted.append(
                    {
                        "title": r.title,
                        "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet)[:300],
                        "source": r.source,
                    }
                )

            return {
                "success": True,
                "query": query,
                "language": language,
                "results": formatted,
                "count": len(formatted),
            }

        except Exception as e:
            logger.error(f"search_wikipedia interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "query": query,
                "results": [],
            }

    return search_wikipedia


def _make_search_arxiv(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der search_arxiv-Funktion."""

    def search_arxiv(query: str) -> dict:
        """
        Durchsucht arXiv für wissenschaftliche Paper.

        Args:
            query: Suchbegriff (z.B. "transformer neural network")

        Returns:
            Dict mit arXiv-Ergebnissen (Titel, Zusammenfassung, Links)

        Beispiele:
            >>> search_arxiv("attention is all you need")
            >>> search_arxiv("large language model")
        """
        try:
            results = ArXivSearcher().search(query, max_results=5)

            formatted = []
            for r in results:
                formatted.append(
                    {
                        "title": r.title,
                        "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet)[:500],
                        "source": r.source,
                    }
                )

            return {
                "success": True,
                "query": query,
                "results": formatted,
                "count": len(formatted),
            }

        except Exception as e:
            logger.error(f"search_arxiv interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "query": query,
                "results": [],
            }

    return search_arxiv


def _make_search_gesti(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der search_gesti-Funktion."""

    def search_gesti(query: str) -> dict:
        """
        Durchsucht GESTI (Gefährdungsbeurteilung) der BG BA.

        Sucht nach Gefahrstoffinformationen, Sicherheitsdatenblättern,
        und Arbeitsplatz-Kontaktwerten.

        Args:
            query: Suchbegriff (z.B. "Aceton", "Blei")

        Returns:
            Dict mit GESTI-Ergebnissen

        Beispiele:
            >>> search_gesti("Aceton")
            >>> search_gesti("Holzstaub")
        """
        try:
            results = GESTISearcher().search(query, max_results=5)

            formatted = []
            for r in results:
                formatted.append(
                    {
                        "title": r.title,
                        "url": r.url,
                        "snippet": sanitize_for_prompt(r.snippet)[:300],
                        "source": r.source,
                    }
                )

            return {
                "success": True,
                "query": query,
                "results": formatted,
                "count": len(formatted),
            }

        except Exception as e:
            logger.error(f"search_gesti interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "query": query,
                "results": [],
            }

    return search_gesti


def _make_safe_web_scrape(mcp_tool_decorator: Callable) -> Callable:
    """Erstellt ein MCP-Tool aus der safe_web_scrape-Funktion."""

    def safe_web_scrape(url: str, max_content_length: int = 3000) -> dict:
        """
        Sicheres Scraping einer Webseite.

        Extrahiert Textinhalt, entfernt alle Skripte und Styles.
        Keine Dateioperationen möglich.

        Args:
            url: Vollstaendige URL der Webseite
            max_content_length: Maximale Länge des extrahierten Inhalts

        Returns:
            Dict mit Titel, Inhalt und Links der Seite

        Beispiele:
            >>> safe_web_scrape("https://example.com/article")
        """
        try:
            if not is_safe_url(url):
                return {
                    "success": False,
                    "error": f"URL blockiert: {url}",
                    "url": url,
                }

            html_content = engine.http_client.fetch(url)
            if not html_content:
                return {
                    "success": False,
                    "error": "Inhalt konnte nicht abgerufen werden",
                    "url": url,
                }

            content = sanitize_html_to_text(html_content, max_length=max_content_length)

            try:
                soup = BeautifulSoup(html_content, "html.parser")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else urlparse(url).hostname or "Ohne Titel"
            except Exception:
                title = "Titel unbekannt"

            return {
                "success": True,
                "url": url,
                "title": title,
                "content": sanitize_for_prompt(content),
                "content_length": len(content),
            }

        except Exception as e:
            logger.error(f"safe_web_scrape interner Fehler: {e!s}")
            return {
                "success": False,
                "error": "Ein interner Fehler ist aufgetreten",
                "url": url,
            }

    return safe_web_scrape


# ============================================================
# Eigenstaendiger MCP-Server (optional)
# ============================================================

mcp_research = FastMCP("internet-research-server")


def _register_tools_to_server(mcp_server):
    """Registriert alle Recherche-Tools auf einem MCP-Server."""
    tool_dec = mcp_server.tool

    @tool_dec()
    def internet_research(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_results: int = 5,
        follow_links: bool = False,
    ) -> dict:
        """Sichere Internet-Recherche mit mehreren Quellen."""
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_results = max(1, min(max_results, MAX_SEARCH_RESULTS))
            return engine.search(query=query, sources=source_list, max_results=max_results, follow_links=follow_links)
        except Exception as e:
            logger.error(f"internet_research interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "query": query, "results": []}

    @tool_dec()
    def internet_research_detailed(
        query: str,
        sources: str = "duckduckgo,wikipedia",
        max_pages: int = 5,
    ) -> dict:
        """Sichere Internet-Recherche mit vollständigen Seiteninhalten."""
        try:
            source_list = [s.strip() for s in sources.split(",") if s.strip()]
            max_pages = max(1, min(max_pages, 10))
            return engine.search_and_read(query=query, sources=source_list, max_pages=max_pages)
        except Exception as e:
            logger.error(f"internet_research_detailed interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "query": query, "results": [], "detailed_pages": []}

    @tool_dec()
    def read_webpage(url: str) -> dict:
        """Liest eine spezifische Webseite sicher."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return {"success": False, "error": "Ungültige URL", "url": url}
            if not is_safe_url(url):
                return {"success": False, "error": f"URL blockiert: {url}", "url": url}
            return engine.read_url(url)
        except Exception as e:
            logger.error(f"read_webpage interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}

    @tool_dec()
    def search_wikipedia(query: str, language: str = "de") -> dict:
        """Durchsucht Wikipedia."""
        try:
            if language not in ("de", "en"):
                language = "de"
            results = WikipediaSearcher().search(query, max_results=5)
            formatted = [
                {"title": r.title, "url": r.url, "snippet": sanitize_for_prompt(r.snippet)[:300], "source": r.source}
                for r in results
            ]
            return {
                "success": True,
                "query": query,
                "language": language,
                "results": formatted,
                "count": len(formatted),
            }
        except Exception as e:
            logger.error(f"search_wikipedia interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "query": query, "results": []}

    @tool_dec()
    def search_arxiv(query: str) -> dict:
        """Durchsucht arXiv für wissenschaftliche Paper."""
        try:
            results = ArXivSearcher().search(query, max_results=5)
            formatted = [
                {"title": r.title, "url": r.url, "snippet": sanitize_for_prompt(r.snippet)[:500], "source": r.source}
                for r in results
            ]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_arxiv interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "query": query, "results": []}

    @tool_dec()
    def search_gesti(query: str) -> dict:
        """Durchsucht GESTI (Gefährdungsbeurteilung) der BG BA."""
        try:
            results = GESTISearcher().search(query, max_results=5)
            formatted = [
                {"title": r.title, "url": r.url, "snippet": sanitize_for_prompt(r.snippet)[:300], "source": r.source}
                for r in results
            ]
            return {"success": True, "query": query, "results": formatted, "count": len(formatted)}
        except Exception as e:
            logger.error(f"search_gesti interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "query": query, "results": []}

    @tool_dec()
    def safe_web_scrape(url: str, max_content_length: int = 3000) -> dict:
        """Sicheres Scraping einer Webseite."""
        try:
            if not is_safe_url(url):
                return {"success": False, "error": f"URL blockiert: {url}", "url": url}
            html_content = engine.http_client.fetch(url)
            if not html_content:
                return {"success": False, "error": "Inhalt konnte nicht abgerufen werden", "url": url}
            content = sanitize_html_to_text(html_content, max_length=max_content_length)
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                title_tag = soup.find("title")
                title = title_tag.get_text(strip=True) if title_tag else urlparse(url).hostname or "Ohne Titel"
            except Exception:
                title = "Titel unbekannt"
            return {
                "success": True,
                "url": url,
                "title": title,
                "content": sanitize_for_prompt(content),
                "content_length": len(content),
            }
        except Exception as e:
            logger.error(f"safe_web_scrape interner Fehler: {e!s}")
            return {"success": False, "error": "Ein interner Fehler ist aufgetreten", "url": url}


# Registriere Tools auf dem research-spezifischen Server
_register_tools_to_server(mcp_research)


# ============================================================
# Exportierte Funktionen fuer Integration in bestehenden Server
# ============================================================
# Diese Funktion registriert alle Recherche-Tools auf einem bestehenden Server.


def register_research_tools(mcp_instance):
    """
    Registriert alle Internet-Recherche-Tools auf einem bestehenden MCP-Server.

    Wird vom Hauptserver verwendet.

    Args:
        mcp_instance: FastMCP-Server-Instanz
    """
    _register_tools_to_server(mcp_instance)
