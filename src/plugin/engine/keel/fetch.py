"""Мережа для радара й перевірки фактів. TLS перевіряється завжди, вимкнути не можна:
вузол, що підміняє відповідь, інакше сховав би вразливість від радара безпеки."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

from . import __version__
from .fsutil import read_json, write_json

USER_AGENT = f"keel/{__version__} (developer radar)"
MAX_BYTES = 8 * 1024 * 1024


class FetchError(RuntimeError):
    def __init__(self, kind: str, url: str, detail: str = ""):
        super().__init__(f"{kind}: {url} {detail}".strip())
        self.kind, self.url, self.detail = kind, url, detail


@dataclass
class Response:
    url: str
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    from_cache: bool = False

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class Transport(Protocol):
    def __call__(self, url: str, method: str, data: bytes | None,
                 headers: dict[str, str], timeout: float) -> Response: ...


def check_url(url: str, resolver: Callable[[str], list[str]] | None = None) -> None:
    """Лише https і лише публічні адреси: сторінка не має змусити нас читати внутрішню мережу."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise FetchError("blocked", url, "дозволено лише https")
    resolver = resolver or _resolve
    try:
        addresses = resolver(parts.hostname)
    except OSError as exc:
        raise FetchError("net", url, str(exc)) from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global:
            raise FetchError("blocked", url, "непублічна адреса")


def _resolve(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443)})


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _real_transport(url: str, method: str, data: bytes | None, headers: dict[str, str],
                    timeout: float) -> Response:
    check_url(url)
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _CheckedRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=timeout) as reply:
            body = reply.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise FetchError("too_large", url)
            return Response(reply.geturl(), reply.status, body, dict(reply.headers.items()))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return Response(url, 304, b"", dict(exc.headers.items()))
        raise FetchError("http", url, str(exc.code)) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLError):
            raise FetchError("tls", url, str(exc.reason)) from exc
        raise FetchError("net", url, str(exc.reason)) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise FetchError("timeout", url) from exc


_transport: Transport = _real_transport


def set_transport(transport: Transport | None) -> None:
    """Підміна для тестів і записаних прогонів."""
    global _transport
    _transport = transport or _real_transport


def fetch(url: str, *, method: str = "GET", data: bytes | None = None,
          headers: dict[str, str] | None = None, timeout: float = 20,
          cache_dir: Path | None = None) -> Response:
    send = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
    meta_path = body_path = None
    if cache_dir is not None and method == "GET":
        key = hashlib.sha256(url.encode()).hexdigest()[:24]
        meta_path, body_path = Path(cache_dir) / f"{key}.json", Path(cache_dir) / f"{key}.body"
        cached = read_json(meta_path)
        if cached and body_path.exists():
            if cached.get("etag"):
                send["If-None-Match"] = cached["etag"]
            if cached.get("modified"):
                send["If-Modified-Since"] = cached["modified"]
    reply = _transport(url, method, data, send, timeout)
    if reply.status == 304 and body_path is not None and body_path.exists():
        return Response(url, 200, body_path.read_bytes(), reply.headers, from_cache=True)
    if meta_path is not None and reply.status == 200:
        lowered = {k.lower(): v for k, v in reply.headers.items()}
        body_path.parent.mkdir(parents=True, exist_ok=True)
        body_path.write_bytes(reply.body)
        write_json(meta_path, {"url": url, "etag": lowered.get("etag"),
                               "modified": lowered.get("last-modified")})
    return reply


class ReplayTransport:
    """Відтворює записані відповіді з теки: ключ `METHOD url` у manifest.json -> файл або код."""

    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.manifest = read_json(self.dir / "manifest.json", {})

    def __call__(self, url, method, data, headers, timeout):
        key = f"{method} {url}"
        if method == "POST" and data:
            key += " " + hashlib.sha256(data).hexdigest()[:12]
        entry = self.manifest.get(key)
        if entry is None:
            raise FetchError("net", url, f"немає запису для {key}")
        if isinstance(entry, int):
            raise FetchError("http", url, str(entry))
        return Response(url, 200, (self.dir / entry).read_bytes())
