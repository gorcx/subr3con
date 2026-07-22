from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.structures import CaseInsensitiveDict

from ..models import SubdomainResult

HOST_RE_TEMPLATE = r"([a-zA-Z0-9][a-zA-Z0-9_.-]*\.){domain}"
HOST_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.IGNORECASE)


@dataclass
class SourceContext:
    domain: str
    timeout: float = 25
    debug: bool = False


class Source:
    name = "source"
    confidence = "medium"
    foreground = False

    def __init__(self, context: SourceContext):
        self.context = context
        self.last_error: str | None = None
        self.timed_out = False
        self.skipped_reason: str | None = None
        self.request_count = 0
        self.cache_hits = 0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            }
        )

    def debug(self, message: str) -> None:
        if self.context.debug:
            print(f"[debug:{self.name}] {message}", file=sys.stderr, flush=True)

    def skip(self, reason: str) -> list:
        self.skipped_reason = reason
        self.debug(reason)
        return []

    def get(self, url: str, **kwargs) -> requests.Response | None:
        cache_enabled = os.environ.get("SUBR3CON_HTTP_CACHE", "1").lower() in {"1", "true", "yes", "on"}
        cache_key = response_cache_key(url, kwargs)
        if cache_enabled and (cached := load_cached_response(cache_key)) is not None:
            self.cache_hits += 1
            self.last_error = None if cached.status_code < 400 else f"HTTP {cached.status_code}"
            self.debug(f"CACHE {cached.status_code} {url}")
            return cached

        retries = max(0, int(os.environ.get("SUBR3CON_HTTP_RETRIES", 2)))
        backoff = max(0.0, float(os.environ.get("SUBR3CON_HTTP_BACKOFF", 0.5)))
        max_wait = max(0.0, float(os.environ.get("SUBR3CON_HTTP_RETRY_MAX_WAIT", 8)))
        retry_statuses = {429, 500, 502, 503, 504}

        for attempt in range(retries + 1):
            self.debug(f"GET {url} attempt={attempt + 1}/{retries + 1}")
            started = time.time()
            self.request_count += 1
            try:
                response = self.session.get(url, timeout=self.context.timeout, **kwargs)
            except Exception as exc:
                self.last_error = str(exc)
                self.timed_out = isinstance(exc, requests.Timeout)
                self.debug(f"request failed: {exc}")
                if attempt < retries:
                    time.sleep(min(max_wait, backoff * (2**attempt)))
                    continue
                return None

            elapsed = time.time() - started
            self.debug(f"HTTP {response.status_code}, {len(response.content)} bytes, {elapsed:.2f}s")
            if response.status_code in retry_statuses and attempt < retries:
                retry_after = parse_retry_after(response.headers.get("Retry-After"))
                wait = retry_after if retry_after is not None else backoff * (2**attempt)
                self.debug(f"retrying HTTP {response.status_code} in {min(max_wait, wait):.2f}s")
                time.sleep(min(max_wait, wait))
                continue

            self.last_error = None if response.status_code < 400 else f"HTTP {response.status_code}"
            self.timed_out = False
            if cache_enabled and response.status_code in {200, 404}:
                save_cached_response(cache_key, response)
            return response
        return None

    def result(
        self,
        host: str,
        ip: str | None = None,
        confidence: str | None = None,
        metadata: dict | None = None,
    ) -> SubdomainResult | None:
        host = normalize_host(host)
        if not is_subdomain(host, self.context.domain):
            return None
        return SubdomainResult(
            host=host,
            source=self.name,
            ip=ip,
            confidence=confidence or self.confidence,
            metadata=metadata or {},
        )

    def extract_hosts(self, text: str) -> list[str]:
        pattern = re.compile(HOST_RE_TEMPLATE.format(domain=re.escape(self.context.domain)), re.I)
        return sorted({normalize_host(match.group(0)) for match in pattern.finditer(text)})

    def run(self) -> list[SubdomainResult]:
        raise NotImplementedError


def normalize_host(host: str) -> str:
    host = re.sub(r"<.*?>", "", host)
    host = host.strip().strip(".").lower()
    if "@" in host:
        host = host[host.find("@") + 1 :]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def is_subdomain(host: str, domain: str) -> bool:
    return bool(host.endswith(f".{domain}") and is_valid_hostname(host))


def is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253 or "*" in host:
        return False
    return all(HOST_LABEL_RE.fullmatch(label) for label in host.split("."))


class CachedResponse:
    def __init__(self, status_code: int, text: str, headers: dict | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = CaseInsensitiveDict(headers or {})
        self.content = text.encode("utf-8")
        self.from_cache = True

    def __bool__(self) -> bool:
        return self.status_code < 400

    def json(self):
        return json.loads(self.text)


def cache_directory() -> Path:
    configured = os.environ.get("SUBR3CON_CACHE_DIR")
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "subr3con-cache"


def response_cache_key(url: str, kwargs: dict) -> str:
    relevant = {
        "url": url,
        "params": kwargs.get("params"),
        "headers": kwargs.get("headers"),
        "cookies": kwargs.get("cookies"),
    }
    payload = json.dumps(relevant, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_cached_response(cache_key: str) -> CachedResponse | None:
    path = cache_directory() / "http" / f"{cache_key}.json"
    ttl = max(0.0, float(os.environ.get("SUBR3CON_CACHE_TTL", 900)))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - float(payload["stored_at"]) > ttl:
            return None
        return CachedResponse(int(payload["status_code"]), str(payload["text"]), dict(payload.get("headers", {})))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_cached_response(cache_key: str, response) -> None:
    directory = cache_directory() / "http"
    path = directory / f"{cache_key}.json"
    payload = {
        "stored_at": time.time(),
        "status_code": response.status_code,
        "text": response.text,
        "headers": dict(response.headers),
    }
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    except OSError:
        return


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
