#!/usr/bin/env python3
"""Proxy VLC's HTTP interface with CORS."""

from __future__ import annotations

import argparse
import base64
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8090
DEFAULT_VLC_URL = "http://127.0.0.1:8080/"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local CORS proxy for VLC's HTTP server."
    )
    parser.add_argument("--bind", default=DEFAULT_BIND, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Proxy port")
    parser.add_argument(
        "--vlc-url",
        default=os.environ.get("VLC_HTTP_URL", DEFAULT_VLC_URL),
        help="Base URL for VLC's HTTP interface",
    )
    parser.add_argument(
        "--vlc-user",
        default=os.environ.get("VLC_HTTP_USER", ""),
        help="VLC HTTP username, usually blank",
    )
    parser.add_argument(
        "--vlc-password",
        default=os.environ.get("VLC_HTTP_PASSWORD", ""),
        help="VLC HTTP password, or set VLC_HTTP_PASSWORD",
    )
    parser.add_argument(
        "--allowed-origin",
        required=True,
        help="Allowed CORS domain, such as example.com",
    )
    return parser.parse_args()


class VlcCorsProxy(BaseHTTPRequestHandler):
    server_version = "VlcCorsProxy/1.0"

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        requested_headers = self.headers.get("Access-Control-Request-Headers")
        if requested_headers:
            self.send_header("Access-Control-Allow-Headers", requested_headers)
        else:
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self) -> None:
        self.proxy_request()

    def do_POST(self) -> None:
        self.proxy_request()

    def do_PUT(self) -> None:
        self.proxy_request()

    def do_DELETE(self) -> None:
        self.proxy_request()

    def proxy_request(self) -> None:
        target_url = self.server.vlc_url.rstrip("/") + "/" + self.path.lstrip("/")
        body = self.read_body()
        headers = self.forward_headers()
        auth_header = self.server.auth_header
        if auth_header:
            headers["Authorization"] = auth_header

        request = Request(target_url, data=body, headers=headers, method=self.command)
        try:
            with urlopen(request, timeout=15) as response:
                self.send_response(response.status)
                self.send_cors_headers()
                self.forward_response_headers(response.headers.items())
                self.end_headers()
                self.wfile.write(response.read())
        except HTTPError as error:
            self.send_response(error.code)
            self.send_cors_headers()
            self.forward_response_headers(error.headers.items())
            self.end_headers()
            self.wfile.write(error.read())
        except URLError as error:
            self.send_response(502)
            self.send_cors_headers()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Could not reach VLC HTTP server: {error.reason}\n".encode())

    def read_body(self) -> bytes | None:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return None
        return self.rfile.read(content_length)

    def forward_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        for name, value in self.headers.items():
            lower_name = name.lower()
            if lower_name in HOP_BY_HOP_HEADERS:
                continue
            if lower_name in {"host", "origin", "referer", "content-length"}:
                continue
            headers[name] = value
        return headers

    def forward_response_headers(self, headers: list[tuple[str, str]]) -> None:
        for name, value in headers:
            lower_name = name.lower()
            if lower_name in HOP_BY_HOP_HEADERS:
                continue
            if lower_name in {"access-control-allow-origin", "access-control-allow-credentials"}:
                continue
            self.send_header(name, value)

    def send_cors_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if self.server.origin_re.match(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


class VlcCorsServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        vlc_url: str,
        auth_header: str | None,
        origin_re: re.Pattern[str],
    ) -> None:
        super().__init__(server_address, handler_class)
        self.vlc_url = normalize_base_url(vlc_url)
        self.auth_header = auth_header
        self.origin_re = origin_re


def normalize_base_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("--vlc-url must be an absolute http(s) URL")
    return url if url.endswith("/") else f"{url}/"


def build_origin_regex(domain: str) -> re.Pattern[str]:
    parsed = urlsplit(f"//{domain}")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("--allowed-origin must be a hostname only, such as example.com") from error

    if (
        parsed.scheme
        or parsed.username
        or parsed.password
        or port
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.netloc != domain
    ):
        raise ValueError("--allowed-origin must be a hostname only, such as example.com")

    labels = domain.split(".")
    if (
        len(labels) < 2
        or any(not label for label in labels)
        or any(not re.fullmatch(r"[a-z0-9-]+", label, re.I) for label in labels)
        or any(label.startswith("-") or label.endswith("-") for label in labels)
    ):
        raise ValueError("--allowed-origin must be a valid hostname, such as example.com")

    escaped_domain = re.escape(domain)
    return re.compile(rf"^https?://(?:[a-z0-9-]+\.)*{escaped_domain}(?::\d+)?$", re.I)


def build_auth_header(user: str, password: str) -> str | None:
    if not password:
        return None
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def main() -> None:
    args = parse_args()
    auth_header = build_auth_header(args.vlc_user, args.vlc_password)
    origin_re = build_origin_regex(args.allowed_origin)
    server = VlcCorsServer(
        (args.bind, args.port),
        VlcCorsProxy,
        vlc_url=args.vlc_url,
        auth_header=auth_header,
        origin_re=origin_re,
    )
    print(f"Proxy listening on http://{args.bind}:{args.port}")
    print(f"Forwarding to {server.vlc_url}")
    server.serve_forever()


if __name__ == "__main__":
    main()
