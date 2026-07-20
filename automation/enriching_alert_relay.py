#!/usr/bin/env python3
"""Source-restricted SIEM relay with fail-open CTI/Shodan enrichment."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

SCHEMA = "cti-shodan-enrichment/v1"
MAX_BODY = 1024 * 1024


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect_not_allowed", headers, fp)


class AbsoluteDeadlineConnectionMixin:
    def __init__(self, *args: Any, absolute_deadline: float, **kwargs: Any) -> None:
        self._deadline_expired = False
        super().__init__(*args, **kwargs)
        self._deadline_timer = threading.Timer(absolute_deadline, self._abort_for_deadline)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _abort_for_deadline(self) -> None:
        self._deadline_expired = True
        active_socket = getattr(self, "_deadline_socket", None) or getattr(self, "sock", None)
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def connect(self) -> None:
        if self._deadline_expired:
            raise TimeoutError("absolute_http_deadline")
        getattr(super(), "connect")()
        self._deadline_socket = getattr(self, "sock", None)
        if self._deadline_expired:
            self._abort_for_deadline()
            raise TimeoutError("absolute_http_deadline")

    def cancel_deadline(self) -> None:
        self._deadline_timer.cancel()


class AbsoluteDeadlineHTTPConnection(AbsoluteDeadlineConnectionMixin, http.client.HTTPConnection):
    pass


class AbsoluteDeadlineHTTPSConnection(AbsoluteDeadlineConnectionMixin, http.client.HTTPSConnection):
    pass


def _deadline_do_open(handler: Any, connection_class: Any, request: Any, deadline: float, **kwargs: Any) -> Any:
    holder: dict[str, Any] = {}

    def factory(host: str, **connection_kwargs: Any) -> Any:
        connection = connection_class(host, absolute_deadline=deadline, **connection_kwargs)
        holder["connection"] = connection
        return connection

    try:
        response = handler.do_open(factory, request, **kwargs)
    except BaseException:
        connection = holder.get("connection")
        if connection is not None:
            connection.cancel_deadline()
        raise
    original_close = response.close

    def close_with_deadline() -> None:
        try:
            original_close()
        finally:
            holder["connection"].cancel_deadline()

    response.close = close_with_deadline
    response.absolute_deadline_connection = holder["connection"]
    return response


class AbsoluteDeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, deadline: float) -> None:
        super().__init__()
        self.deadline = deadline

    def http_open(self, req: Any) -> Any:
        return _deadline_do_open(self, AbsoluteDeadlineHTTPConnection, req, self.deadline)


class AbsoluteDeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, deadline: float) -> None:
        super().__init__()
        self.deadline = deadline

    def https_open(self, req: Any) -> Any:
        return _deadline_do_open(
            self,
            AbsoluteDeadlineHTTPSConnection,
            req,
            self.deadline,
            context=getattr(self, "_context", None),
            check_hostname=getattr(self, "_check_hostname", None),
        )


def build_deadline_opener(deadline: float) -> Any:
    return urllib.request.build_opener(
        NoRedirectHandler(),
        AbsoluteDeadlineHTTPHandler(deadline),
        AbsoluteDeadlineHTTPSHandler(deadline),
    )


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler())
JSON_TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'+-.^_`|~")
URL_SAFE_SECRET_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-")


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, server_address, handler, *, allowed_sources, max_connections, read_timeout, connection_deadline):
        self.allowed_sources = set(allowed_sources)
        self.read_timeout = read_timeout
        self.connection_deadline = connection_deadline
        self._request_slots = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, handler)

    def verify_request(self, request: Any, client_address: tuple[str, int]) -> bool:
        return client_address[0] in self.allowed_sources

    def process_request(self, request: Any, client_address: tuple[str, int]) -> None:
        request.settimeout(self.read_timeout)
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: tuple[str, int]) -> None:
        timer = threading.Timer(self.connection_deadline, self._expire_request, args=(request,))
        timer.daemon = True
        timer.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self._request_slots.release()

    @staticmethod
    def _expire_request(request: Any) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def read_bounded_bytes(stream: Any, limit: int) -> bytes:
    body = stream.read(limit + 1)
    guard = getattr(stream, "absolute_deadline_connection", None)
    if guard is not None and guard._deadline_expired:
        raise TimeoutError("absolute_http_deadline")
    if len(body) > limit:
        raise ValueError("response_too_large")
    return body


def is_json_media_type(raw: Any) -> bool:
    media_type = str(raw or "").partition(";")[0].strip().lower()
    if media_type == "application/json":
        return True
    prefix = "application/"
    if not media_type.startswith(prefix):
        return False
    subtype = media_type[len(prefix):]
    base = subtype[:-5] if subtype.endswith("+json") else ""
    return bool(base) and all(character in JSON_TOKEN_CHARS for character in subtype)


def reject_nonfinite_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON constant: {value}")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate_json_key")
        output[key] = value
    return output


def strict_json_loads(body: bytes | str) -> Any:
    try:
        value = json.loads(
            body,
            parse_constant=reject_nonfinite_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("invalid_json") from exc
    validate_json_shape(value)
    return value


def read_bounded_json(response: Any, limit: int) -> dict[str, Any]:
    if not is_json_media_type(response.headers.get("Content-Type", "")):
        raise ValueError("json_content_type_required")
    value = strict_json_loads(read_bounded_bytes(response, limit))
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def validate_json_shape(value: Any, max_depth: int = 32, max_nodes: int = 10_000) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ValueError("json_shape_exceeds_limit")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise ValueError("nonfinite_json_number")


def parse_json_object(body: bytes) -> dict[str, Any]:
    value = strict_json_loads(body)
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def bounded_float(name: str, raw: str, minimum: float, maximum: float) -> float:
    parts = raw.split(".")
    if not raw.isascii() or len(parts) > 2 or any(not part.isdecimal() for part in parts):
        raise ValueError(f"{name} must be an unsigned decimal number")
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def bounded_int(name: str, raw: str, minimum: int, maximum: int) -> int:
    if not raw.isascii() or not raw.isdecimal():
        raise ValueError(f"{name} must be an unsigned decimal integer")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def validated_ipv4(name: str, raw: str) -> str:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an IPv4 address") from exc
    if address.version != 4:
        raise ValueError(f"{name} must be an IPv4 address")
    return str(address)


def validated_ascii_secret(name: str, value: str, *, url_safe: bool = False) -> str:
    if not 16 <= len(value) <= 4096 or any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise ValueError(f"{name} must be 16-4096 printable non-whitespace ASCII characters")
    if url_safe and any(character not in URL_SAFE_SECRET_CHARS for character in value):
        raise ValueError(f"{name} must use URL-safe characters")
    return value


def validated_http_url(name: str, raw: str) -> str:
    if any(character.isspace() or ord(character) < 32 for character in raw):
        raise ValueError(f"{name} contains invalid characters")
    try:
        parsed = urllib.parse.urlsplit(raw)
        parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} is malformed") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be an HTTP(S) URL without user info")
    hostname = parsed.hostname
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        candidate = hostname[:-1] if hostname.endswith(".") else hostname
        labels = candidate.split(".")
        if (
            not candidate.isascii()
            or not 1 <= len(candidate) <= 253
            or any(
                not 1 <= len(label) <= 63
                or label.startswith("-")
                or label.endswith("-")
                or any(not (character.isascii() and (character.isalnum() or character == "-")) for character in label)
                for label in labels
            )
        ):
            raise ValueError(f"{name} contains an invalid hostname")
    return raw


def unavailable_enrichment() -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "observables": [],
        "verdict": "context_only",
        "warning": "Enrichment unavailable; original alert forwarded.",
    }


def _bounded_string_list(value: Any, count: int, width: int) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= count
        and all(isinstance(item, str) and len(item) <= width for item in value)
    )


def _bounded_int_value(value: Any, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _valid_opencti(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) - {"matched", "match_count", "max_score", "types", "last_updated"}:
        return False
    return (
        isinstance(value.get("matched"), bool)
        and _bounded_int_value(value.get("match_count"), 0, 10)
        and _bounded_int_value(value.get("max_score"), 0, 100)
        and _bounded_string_list(value.get("types"), 10, 128)
        and (value.get("last_updated") is None or isinstance(value.get("last_updated"), str))
        and len(value.get("last_updated") or "") <= 64
    )


def _valid_shodan(value: Any) -> bool:
    allowed = {
        "found", "organization", "isp", "asn", "country_code", "city", "ports",
        "hostnames", "vulnerabilities", "tags", "last_update",
    }
    if not isinstance(value, dict) or set(value) - allowed or not isinstance(value.get("found"), bool):
        return False
    for field, width in (("organization", 256), ("isp", 256), ("asn", 64), ("country_code", 8), ("city", 256), ("last_update", 64)):
        if value.get(field) is not None and (not isinstance(value[field], str) or len(value[field]) > width):
            return False
    ports = value.get("ports")
    return (
        isinstance(ports, list)
        and len(ports) <= 25
        and all(_bounded_int_value(port, 1, 65535) for port in ports)
        and _bounded_string_list(value.get("hostnames"), 10, 255)
        and _bounded_string_list(value.get("vulnerabilities"), 25, 128)
        and _bounded_string_list(value.get("tags"), 10, 128)
    )


def _valid_observable(value: Any) -> bool:
    required = {"type", "value", "cache_hit", "attention", "opencti", "shodan", "errors"}
    if not isinstance(value, dict) or set(value) != required:
        return False
    observable_value = value.get("value")
    if not isinstance(observable_value, str):
        return False
    try:
        address = ipaddress.ip_address(observable_value)
    except ValueError:
        return False
    errors = value.get("errors")
    return (
        value.get("type") == "ipv4"
        and address.version == 4
        and address.is_global
        and not address.is_multicast
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not address.is_unspecified
        and isinstance(value.get("cache_hit"), bool)
        and value.get("attention") in {"informational", "review", "elevated"}
        and _valid_opencti(value.get("opencti"))
        and _valid_shodan(value.get("shodan"))
        and isinstance(errors, dict)
        and not set(errors) - {"opencti", "shodan", "cache"}
        and all(isinstance(item, str) and len(item) <= 64 for item in errors.values())
    )


def valid_enrichment(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) - {"schema", "status", "observables", "verdict", "warning", "reason"}:
        return False
    status = value.get("status")
    observables = value.get("observables")
    if (
        value.get("schema") != SCHEMA
        or status not in {"enriched", "partial", "skipped", "unavailable"}
        or value.get("verdict") != "context_only"
        or not isinstance(value.get("warning"), str)
        or len(value["warning"]) > 256
        or not isinstance(observables, list)
        or len(observables) > 10
        or not all(_valid_observable(observable) for observable in observables)
    ):
        return False
    if status == "skipped":
        return not observables and value.get("reason") == "no_supported_public_ipv4"
    if status == "unavailable":
        return not observables and "reason" not in value
    if "reason" in value or not observables:
        return False
    has_errors = any(observable["errors"] for observable in observables)
    return (status == "partial") == has_errors


def attach_enrichment(payload: dict[str, Any], lookup: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    enriched_payload = dict(payload)
    try:
        enrichment = lookup(payload)
        if not valid_enrichment(enrichment):
            enrichment = unavailable_enrichment()
    except Exception:
        enrichment = unavailable_enrichment()
    field = "cti_enrichment"
    if field in enriched_payload:
        field = "relay_cti_enrichment"
        suffix = 2
        while field in enriched_payload:
            field = f"relay_cti_enrichment_{suffix}"
            suffix += 1
    enriched_payload[field] = enrichment
    return enriched_payload


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "mayuri-alert-relay/2.0"

    @property
    def app(self) -> Any:
        return self.server.app  # type: ignore[attr-defined]

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _enrich(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.app["enrichment_url"],
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers={
                "Authorization": "Bearer " + self.app["enrichment_token"],
                "Content-Type": "application/json",
                "User-Agent": "mayuri-alert-relay/2.0",
            },
            method="POST",
        )
        opener = build_deadline_opener(self.app["enrichment_deadline"])
        try:
            with opener.open(request, timeout=self.app["enrichment_timeout"]) as response:
                return read_bounded_json(response, self.app["max_response"])
        except urllib.error.HTTPError as exc:
            exc.close()
            raise

    def _route(self) -> str | None:
        if self.path == f"/splunk/{self.app['splunk_token']}":
            return self.app["splunk_upstream"]
        wazuh_token = self.app.get("wazuh_token")
        if wazuh_token and self.path == f"/wazuh/{wazuh_token}":
            return self.app["wazuh_upstream"]
        return None

    def do_POST(self) -> None:
        if self.client_address[0] != self.app["allowed_source"]:
            self._reply(403, {"error": "source_not_allowed"})
            return
        upstream = self._route()
        if upstream is None:
            self._reply(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reply(400, {"error": "invalid_content_length"})
            return
        if length <= 0 or length > self.app["max_body"]:
            self._reply(413, {"error": "invalid_body_size"})
            return
        try:
            parsed = parse_json_object(self.rfile.read(length))
        except ValueError:
            self._reply(400, {"error": "invalid_json"})
            return

        forwarded = attach_enrichment(parsed, self._enrich)
        request = urllib.request.Request(
            upstream,
            data=json.dumps(forwarded, separators=(",", ":")).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "mayuri-alert-relay/2.0"},
            method="POST",
        )
        try:
            opener = build_deadline_opener(self.app["upstream_deadline"])
            with opener.open(request, timeout=self.app["upstream_timeout"]) as response:
                upstream_body = read_bounded_bytes(response, self.app["max_response"])
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(upstream_body)))
                self.end_headers()
                self.wfile.write(upstream_body)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            self._reply(502, {"error": "upstream_http_error", "status": status})
        except ValueError:
            self._reply(502, {"error": "upstream_response_invalid"})
        except Exception:
            self._reply(502, {"error": "upstream_unreachable"})

    def do_GET(self) -> None:
        if self.path == "/health" and self.client_address[0] == self.app["allowed_source"]:
            self._reply(200, {"status": "ok", "enrichment": "configured"})
            return
        self._reply(404, {"error": "not_found"})

    def log_message(self, format: str, *args: Any) -> None:
        status = str(args[1]) if len(args) > 1 else "unknown"
        print(f"{self.client_address[0]} - status={status}", flush=True)


def main() -> int:
    required = [
        "RELAY_LISTEN_HOST",
        "RELAY_ALLOWED_SOURCE",
        "RELAY_TOKEN",
        "RELAY_UPSTREAM",
        "RELAY_ENRICHMENT_URL",
        "RELAY_ENRICHMENT_TOKEN",
    ]
    missing = [key for key in required if not os.environ.get(key)]
    if missing:
        raise SystemExit("missing required environment keys: " + ",".join(missing))
    listen_host = validated_ipv4("RELAY_LISTEN_HOST", os.environ["RELAY_LISTEN_HOST"])
    allowed_source = validated_ipv4("RELAY_ALLOWED_SOURCE", os.environ["RELAY_ALLOWED_SOURCE"])
    splunk_token = validated_ascii_secret("RELAY_TOKEN", os.environ["RELAY_TOKEN"], url_safe=True)
    wazuh_token_raw = os.environ.get("RELAY_WAZUH_TOKEN")
    wazuh_token = (
        validated_ascii_secret("RELAY_WAZUH_TOKEN", wazuh_token_raw, url_safe=True) if wazuh_token_raw else None
    )
    enrichment_token = validated_ascii_secret("RELAY_ENRICHMENT_TOKEN", os.environ["RELAY_ENRICHMENT_TOKEN"])
    server = BoundedThreadingHTTPServer(
        (listen_host, bounded_int("RELAY_LISTEN_PORT", os.environ.get("RELAY_LISTEN_PORT", "8766"), 1, 65535)),
        RelayHandler,
        allowed_sources={allowed_source},
        max_connections=bounded_int(
            "RELAY_MAX_CONNECTIONS", os.environ.get("RELAY_MAX_CONNECTIONS", "16"), 1, 128
        ),
        read_timeout=bounded_float("RELAY_READ_TIMEOUT", os.environ.get("RELAY_READ_TIMEOUT", "5"), 0.1, 30.0),
        connection_deadline=bounded_float(
            "RELAY_CONNECTION_DEADLINE", os.environ.get("RELAY_CONNECTION_DEADLINE", "15"), 0.5, 60.0
        ),
    )
    server.app = {  # type: ignore[attr-defined]
        "allowed_source": allowed_source,
        "splunk_token": splunk_token,
        "splunk_upstream": validated_http_url("RELAY_UPSTREAM", os.environ["RELAY_UPSTREAM"]),
        "wazuh_token": wazuh_token,
        "wazuh_upstream": (
            validated_http_url("RELAY_WAZUH_UPSTREAM", os.environ["RELAY_WAZUH_UPSTREAM"])
            if os.environ.get("RELAY_WAZUH_UPSTREAM")
            else None
        ),
        "enrichment_url": validated_http_url("RELAY_ENRICHMENT_URL", os.environ["RELAY_ENRICHMENT_URL"]),
        "enrichment_token": enrichment_token,
        "enrichment_timeout": bounded_float(
            "RELAY_ENRICHMENT_TIMEOUT", os.environ.get("RELAY_ENRICHMENT_TIMEOUT", "12"), 0.1, 60.0
        ),
        "enrichment_deadline": bounded_float(
            "RELAY_ENRICHMENT_DEADLINE", os.environ.get("RELAY_ENRICHMENT_DEADLINE", "15"), 0.5, 60.0
        ),
        "upstream_timeout": bounded_float(
            "RELAY_UPSTREAM_TIMEOUT", os.environ.get("RELAY_UPSTREAM_TIMEOUT", "90"), 0.1, 180.0
        ),
        "upstream_deadline": bounded_float(
            "RELAY_UPSTREAM_DEADLINE", os.environ.get("RELAY_UPSTREAM_DEADLINE", "120"), 0.5, 180.0
        ),
        "max_body": bounded_int("RELAY_MAX_BODY", os.environ.get("RELAY_MAX_BODY", str(MAX_BODY)), 1024, MAX_BODY),
        "max_response": bounded_int(
            "RELAY_MAX_RESPONSE", os.environ.get("RELAY_MAX_RESPONSE", str(MAX_BODY)), 1024, MAX_BODY
        ),
    }
    if server.app["wazuh_token"] and not server.app["wazuh_upstream"]:  # type: ignore[index]
        raise SystemExit("RELAY_WAZUH_UPSTREAM is required when RELAY_WAZUH_TOKEN is set")
    print("mayuri alert relay ready", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
