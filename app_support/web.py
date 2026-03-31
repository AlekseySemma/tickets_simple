from urllib.parse import urlencode, urlsplit

from fastapi import Request


def safe_next(next_url: str | None, fallback: str = "/web") -> str:
    next_value = (next_url or "").strip()
    if not next_value:
        return fallback
    return next_value if next_value.startswith("/web") else fallback


def append_query_params(url: str, **params: object) -> str:
    items: list[tuple[str, str]] = []
    for key, value in params.items():
        if value is None or value is False or value == "":
            continue
        items.append((key, "1" if value is True else str(value)))
    if not items:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{urlencode(items)}"


def first_header_value(value: str | None) -> str:
    return (value or "").split(",")[0].strip()


def get_client_ip(request: Request | None) -> str:
    if request is None:
        return "unknown"
    forwarded_for = first_header_value(request.headers.get("x-forwarded-for"))
    if forwarded_for:
        return forwarded_for
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def normalize_origin(value: str | None) -> tuple[str, str, int] | None:
    raw = (value or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    return scheme, host, port


def request_origin(request: Request) -> tuple[str, str, int] | None:
    forwarded_proto = first_header_value(request.headers.get("x-forwarded-proto"))
    forwarded_host = first_header_value(request.headers.get("x-forwarded-host"))
    host_header = first_header_value(request.headers.get("host"))
    scheme = (forwarded_proto or request.url.scheme or "http").lower()
    host = forwarded_host or host_header or request.url.netloc
    if not host:
        return None
    return normalize_origin(f"{scheme}://{host}")

