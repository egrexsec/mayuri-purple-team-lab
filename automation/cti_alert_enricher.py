#!/usr/bin/env python3
"""Authenticated, cached OpenCTI + Shodan enrichment for SIEM alert payloads."""

from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

SCHEMA = "cti-shodan-enrichment/v1"
IPV4_PATTERN = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
CONTEXT_WARNING = "Threat intelligence is context, not proof of maliciousness."
MAX_PROVIDER_RESPONSE = 512 * 1024
MAX_CACHE_ENTRY = 64 * 1024
DEFAULT_MAX_CACHE_ROWS = 10_000
DEFAULT_MAX_CACHE_BYTES = 64 * 1024 * 1024


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


def bounded_text(value: Any, limit: int = 256) -> str | None:
    if value is None:
        return None
    return str(value)[:limit]


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


def extract_public_ipv4s(payload: Any, limit: int = 3) -> list[str]:
    """Return unique, globally routable IPv4 values in encounter order."""
    found: list[str] = []
    seen: set[str] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 12 or len(found) >= limit:
            return
        if isinstance(value, dict):
            for child in value.values():
                visit(child, depth + 1)
                if len(found) >= limit:
                    return
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child, depth + 1)
                if len(found) >= limit:
                    return
        elif isinstance(value, str):
            for candidate in IPV4_PATTERN.findall(value):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                normalized = str(address)
                is_public_unicast = (
                    address.version == 4
                    and address.is_global
                    and not address.is_multicast
                    and not address.is_private
                    and not address.is_loopback
                    and not address.is_link_local
                    and not address.is_reserved
                    and not address.is_unspecified
                )
                if is_public_unicast and normalized not in seen:
                    seen.add(normalized)
                    found.append(normalized)
                    if len(found) >= limit:
                        return

    visit(payload)
    return found


class AlertEnricher:
    def __init__(
        self,
        cache_path: Path,
        opencti_lookup: Callable[[str], dict[str, Any]],
        shodan_lookup: Callable[[str], dict[str, Any]],
        positive_ttl: int = 86400,
        negative_ttl: int = 3600,
        max_observables: int = 3,
        max_cache_rows: int = DEFAULT_MAX_CACHE_ROWS,
        max_cache_bytes: int = DEFAULT_MAX_CACHE_BYTES,
        max_cache_entry: int = MAX_CACHE_ENTRY,
    ) -> None:
        self.cache_path = Path(cache_path)
        self.opencti_lookup = opencti_lookup
        self.shodan_lookup = shodan_lookup
        self.positive_ttl = bounded_int("positive_ttl", str(positive_ttl), 60, 604800)
        self.negative_ttl = bounded_int("negative_ttl", str(negative_ttl), 60, 86400)
        self.max_observables = bounded_int("max_observables", str(max_observables), 1, 10)
        self.max_cache_rows = bounded_int("max_cache_rows", str(max_cache_rows), 1, 100_000)
        self.max_cache_bytes = bounded_int("max_cache_bytes", str(max_cache_bytes), 1024 * 1024, 1024 * 1024 * 1024)
        self.max_cache_entry = bounded_int("max_cache_entry", str(max_cache_entry), 1024, MAX_PROVIDER_RESPONSE)
        self.cache_available = False
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_files = self._cache_files()
            if any(path.is_symlink() for path in cache_files):
                raise OSError("cache_symlink_not_allowed")
            if self._cache_physical_bytes() > self.max_cache_bytes:
                raise OSError("cache_files_exceed_limit")
            if self.cache_path.exists() and self.cache_path.stat().st_size > self._database_byte_limit():
                raise OSError("cache_database_exceeds_reserved_limit")
            if any(path.exists() and path.stat().st_size for path in cache_files[1:]):
                raise OSError("cache_sidecar_state_not_allowed")
            with closing(sqlite3.connect(self.cache_path, timeout=5)) as connection:
                if str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower() != "delete":
                    raise sqlite3.DatabaseError("cache_journal_mode_not_enforced")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS enrichment_cache "
                    "(observable TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, payload TEXT NOT NULL)"
                )
                self._prune_connection(connection)
                connection.commit()
                max_pages = self._max_cache_pages(connection)
                if int(connection.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
                    raise sqlite3.DatabaseError("cache_database_exceeds_limit")
                connection.execute(f"PRAGMA max_page_count={max_pages}")
            if self._cache_physical_bytes() > self.max_cache_bytes:
                raise OSError("cache_files_exceed_limit")
            self.cache_available = True
        except (OSError, sqlite3.Error):
            self.cache_available = False

    def _cache_files(self) -> list[Path]:
        return [
            self.cache_path,
            Path(str(self.cache_path) + "-wal"),
            Path(str(self.cache_path) + "-journal"),
            Path(str(self.cache_path) + "-shm"),
        ]

    def _cache_physical_bytes(self) -> int:
        return sum(path.stat().st_size for path in self._cache_files() if path.exists())

    def _database_byte_limit(self) -> int:
        return self.max_cache_bytes * 45 // 100

    def _max_cache_pages(self, connection: sqlite3.Connection) -> int:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        return max(1, self._database_byte_limit() // page_size)

    def _prune_connection(self, connection: sqlite3.Connection) -> None:
        connection.execute("DELETE FROM enrichment_cache WHERE expires_at <= ?", (int(time.time()),))
        count = int(connection.execute("SELECT COUNT(*) FROM enrichment_cache").fetchone()[0])
        overflow = max(0, count - self.max_cache_rows)
        if overflow:
            connection.execute(
                "DELETE FROM enrichment_cache WHERE observable IN "
                "(SELECT observable FROM enrichment_cache ORDER BY expires_at ASC, observable ASC LIMIT ?)",
                (overflow,),
            )

    def _connect(self) -> sqlite3.Connection:
        if not self.cache_available:
            raise sqlite3.DatabaseError("cache_unavailable")
        if self._cache_physical_bytes() > self.max_cache_bytes:
            self.cache_available = False
            raise sqlite3.DatabaseError("cache_files_exceed_limit")
        sidecars = self._cache_files()[1:]
        if any(path.name.endswith(("-wal", "-shm")) and path.exists() and path.stat().st_size for path in sidecars):
            self.cache_available = False
            raise sqlite3.DatabaseError("cache_wal_state_not_allowed")
        connection = sqlite3.connect(self.cache_path, timeout=5)
        if str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower() != "delete":
            connection.close()
            self.cache_available = False
            raise sqlite3.DatabaseError("cache_journal_mode_not_enforced")
        max_pages = self._max_cache_pages(connection)
        if int(connection.execute("PRAGMA page_count").fetchone()[0]) > max_pages:
            connection.close()
            raise sqlite3.DatabaseError("cache_database_exceeds_limit")
        actual_limit = int(connection.execute(f"PRAGMA max_page_count={max_pages}").fetchone()[0])
        if actual_limit > max_pages:
            connection.close()
            raise sqlite3.DatabaseError("cache_database_limit_not_enforced")
        return connection

    def _cache_get(self, observable: str) -> dict[str, Any] | None:
        now = int(time.time())
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM enrichment_cache WHERE observable = ? AND expires_at > ?",
                (observable, now),
            ).fetchone()
            connection.execute("DELETE FROM enrichment_cache WHERE expires_at <= ?", (now,))
            connection.commit()
        if not row:
            return None
        encoded = row[0]
        if not isinstance(encoded, str) or len(encoded.encode()) > self.max_cache_entry:
            raise ValueError("invalid_cache_payload")
        value = strict_json_loads(encoded)
        required = {"type", "value", "cache_hit", "attention", "opencti", "shodan", "errors"}
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("type") != "ipv4"
            or value.get("value") != observable
            or value.get("attention") not in {"informational", "review", "elevated"}
            or not isinstance(value.get("opencti"), dict)
            or not isinstance(value.get("shodan"), dict)
            or not isinstance(value.get("errors"), dict)
        ):
            raise ValueError("invalid_cache_payload")
        return value

    def _cache_put(self, observable: str, payload: dict[str, Any], ttl: int) -> None:
        expires_at = int(time.time()) + ttl
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode()) > self.max_cache_entry:
            raise ValueError("cache_entry_too_large")
        with closing(self._connect()) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO enrichment_cache(observable, expires_at, payload) VALUES (?, ?, ?)",
                (observable, expires_at, encoded),
            )
            self._prune_connection(connection)
            connection.commit()
            if self._cache_physical_bytes() > self.max_cache_bytes:
                self.cache_available = False
                raise sqlite3.DatabaseError("cache_files_exceed_limit")

    @staticmethod
    def _attention(opencti: dict[str, Any], shodan: dict[str, Any]) -> str:
        if int(opencti.get("max_score") or 0) >= 80 or shodan.get("vulnerabilities"):
            return "elevated"
        if opencti.get("matched") or shodan.get("found"):
            return "review"
        return "informational"

    def _enrich_one(self, observable: str) -> dict[str, Any]:
        cache_error = False
        try:
            cached = self._cache_get(observable)
        except (sqlite3.Error, ValueError, json.JSONDecodeError):
            cached = None
            cache_error = True
        if cached is not None:
            cached["cache_hit"] = True
            return cached

        errors: dict[str, str] = {}
        try:
            opencti = self.opencti_lookup(observable)
        except Exception:
            opencti = {"matched": False, "match_count": 0, "max_score": 0, "types": []}
            errors["opencti"] = "provider_unavailable"
        try:
            shodan = self.shodan_lookup(observable)
        except Exception:
            shodan = {"found": False, "ports": [], "hostnames": [], "vulnerabilities": [], "tags": []}
            errors["shodan"] = "provider_unavailable"

        result = {
            "type": "ipv4",
            "value": observable,
            "cache_hit": False,
            "attention": self._attention(opencti, shodan),
            "opencti": opencti,
            "shodan": shodan,
            "errors": errors,
        }
        if cache_error:
            errors["cache"] = "unavailable"
        cache_errors = {key: value for key, value in errors.items() if key != "cache"}
        cache_payload = dict(result)
        cache_payload["errors"] = cache_errors
        is_positive = bool(opencti.get("matched") or shodan.get("found")) and not cache_errors
        try:
            self._cache_put(
                observable,
                cache_payload,
                self.positive_ttl if is_positive else self.negative_ttl,
            )
        except (sqlite3.Error, ValueError):
            errors["cache"] = "unavailable"
        return result

    def enrich_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        observables = extract_public_ipv4s(payload, self.max_observables)
        if not observables:
            return {
                "schema": SCHEMA,
                "status": "skipped",
                "observables": [],
                "verdict": "context_only",
                "warning": CONTEXT_WARNING,
                "reason": "no_supported_public_ipv4",
            }
        enriched = [self._enrich_one(value) for value in observables]
        status = "partial" if any(item["errors"] for item in enriched) else "enriched"
        return {
            "schema": SCHEMA,
            "status": status,
            "observables": enriched,
            "verdict": "context_only",
            "warning": CONTEXT_WARNING,
        }


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def read_runtime_secret(credential_name: str, environment_key: str) -> str:
    credentials_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials_directory:
        credential_path = Path(credentials_directory) / credential_name
        if credential_path.is_file():
            value = credential_path.read_text(encoding="utf-8").strip()
            if value:
                return value
    value = os.environ.get(environment_key, "").strip()
    if value:
        return value
    raise RuntimeError(f"missing runtime credential: {credential_name}")


def make_opencti_lookup(
    url: str,
    token: str,
    timeout: float,
    max_response: int = MAX_PROVIDER_RESPONSE,
    opener: Any = None,
    absolute_deadline: float | None = None,
) -> Callable[[str], dict[str, Any]]:
    request_opener = opener if opener is not None else build_deadline_opener(absolute_deadline or timeout)
    query = """query Observable($filters: FilterGroup) {
      stixCyberObservables(first: 10, filters: $filters) {
        edges { node { entity_type observable_value x_opencti_score updated_at } }
      }
    }"""

    def lookup(observable: str) -> dict[str, Any]:
        variables = {
            "filters": {
                "mode": "and",
                "filters": [{"key": "value", "values": [observable], "operator": "eq"}],
                "filterGroups": [],
            }
        }
        request = urllib.request.Request(
            url.rstrip("/") + "/graphql",
            data=json.dumps({"query": query, "variables": variables}).encode(),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request_opener.open(request, timeout=timeout) as response:
                data = read_bounded_json(response, max_response)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise
        if data.get("errors"):
            raise RuntimeError("OpenCTI GraphQL error")
        edges = (((data.get("data") or {}).get("stixCyberObservables") or {}).get("edges") or [])
        nodes = [edge.get("node") or {} for edge in edges]
        scores = [int(node.get("x_opencti_score") or 0) for node in nodes]
        return {
            "matched": bool(nodes),
            "match_count": len(nodes),
            "max_score": max(scores, default=0),
            "types": sorted({str(node.get("entity_type"))[:128] for node in nodes if node.get("entity_type")}),
            "last_updated": max(
                (str(node.get("updated_at"))[:64] for node in nodes if node.get("updated_at")),
                default=None,
            ),
        }

    return lookup


def make_shodan_lookup(
    api_key: str,
    timeout: float,
    max_response: int = MAX_PROVIDER_RESPONSE,
    opener: Any = None,
    absolute_deadline: float | None = None,
) -> Callable[[str], dict[str, Any]]:
    request_opener = opener if opener is not None else build_deadline_opener(absolute_deadline or timeout)
    def lookup(observable: str) -> dict[str, Any]:
        url = "https://api.shodan.io/shodan/host/" + urllib.parse.quote(observable) + "?" + urllib.parse.urlencode(
            {"key": api_key, "minify": "true"}
        )
        try:
            with request_opener.open(url, timeout=timeout) as response:
                data = read_bounded_json(response, max_response)
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if code != 404:
                raise
            return {"found": False, "ports": [], "hostnames": [], "vulnerabilities": [], "tags": []}
        vulnerabilities = data.get("vulns") or []
        if isinstance(vulnerabilities, dict):
            vulnerabilities = list(vulnerabilities)
        return {
            "found": True,
            "organization": bounded_text(data.get("org"), 256),
            "isp": bounded_text(data.get("isp"), 256),
            "asn": bounded_text(data.get("asn"), 64),
            "country_code": bounded_text(data.get("country_code"), 8),
            "city": bounded_text(data.get("city"), 256),
            "ports": sorted({int(port) for port in (data.get("ports") or [])})[:25],
            "hostnames": sorted({str(name)[:255] for name in (data.get("hostnames") or [])})[:10],
            "vulnerabilities": sorted({str(item)[:128] for item in vulnerabilities})[:25],
            "tags": sorted({str(item)[:128] for item in (data.get("tags") or [])})[:10],
            "last_update": bounded_text(data.get("last_update"), 64),
        }

    return lookup


class EnrichmentHandler(BaseHTTPRequestHandler):
    server_version = "cti-alert-enricher/1.0"

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

    def _source_allowed(self) -> bool:
        return self.client_address[0] in self.app["allowed_sources"]

    def do_GET(self) -> None:
        if self.path == "/health" and self._source_allowed():
            self._reply(200, {"status": "ok", "schema": SCHEMA})
            return
        self._reply(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/v1/enrich":
            self._reply(404, {"error": "not_found"})
            return
        if not self._source_allowed():
            self._reply(403, {"error": "source_not_allowed"})
            return
        supplied = self.headers.get("Authorization", "")
        expected = "Bearer " + self.app["token"]
        if not hmac.compare_digest(supplied, expected):
            self._reply(403, {"error": "forbidden"})
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
            payload = parse_json_object(self.rfile.read(length))
        except ValueError:
            self._reply(400, {"error": "invalid_json"})
            return
        try:
            self._reply(200, self.app["enricher"].enrich_alert(payload))
        except Exception:
            self._reply(500, {"error": "enrichment_failed"})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.client_address[0]} - {format % args}", flush=True)


def main() -> int:
    token = read_runtime_secret("enricher_bearer_token", "ENRICHER_BEARER_TOKEN")
    validated_ascii_secret("enricher_bearer_token", token)
    opencti_url = validated_http_url("OPENCTI_URL", os.environ["OPENCTI_URL"])
    opencti_token = read_runtime_secret("opencti_token", "OPENCTI_TOKEN")
    validated_ascii_secret("opencti_token", opencti_token)
    shodan_key = read_runtime_secret("shodan_api_key", "SHODAN_API_KEY")
    validated_ascii_secret("shodan_api_key", shodan_key)
    timeout = bounded_float("ENRICHER_PROVIDER_TIMEOUT", os.environ.get("ENRICHER_PROVIDER_TIMEOUT", "8"), 0.1, 30.0)
    outbound_deadline = bounded_float(
        "ENRICHER_OUTBOUND_DEADLINE", os.environ.get("ENRICHER_OUTBOUND_DEADLINE", "15"), 0.5, 60.0
    )
    provider_max_response = bounded_int(
        "ENRICHER_PROVIDER_MAX_RESPONSE",
        os.environ.get("ENRICHER_PROVIDER_MAX_RESPONSE", str(MAX_PROVIDER_RESPONSE)),
        1024,
        1024 * 1024,
    )
    cache_path = Path(os.environ.get("ENRICHER_CACHE_PATH", "/var/lib/cti-alert-enricher/cache.db"))
    allowed_sources = {item.strip() for item in os.environ["ENRICHER_ALLOWED_SOURCES"].split(",") if item.strip()}
    if not allowed_sources:
        raise ValueError("ENRICHER_ALLOWED_SOURCES must not be empty")
    for source in allowed_sources:
        validated_ipv4("ENRICHER_ALLOWED_SOURCES", source)
    listen_host = validated_ipv4("ENRICHER_LISTEN_HOST", os.environ["ENRICHER_LISTEN_HOST"])
    opencti_lookup = make_opencti_lookup(
        opencti_url, opencti_token, timeout, provider_max_response, absolute_deadline=outbound_deadline
    )
    shodan_lookup = make_shodan_lookup(
        shodan_key, timeout, provider_max_response, absolute_deadline=outbound_deadline
    )
    enricher = AlertEnricher(
        cache_path=cache_path,
        opencti_lookup=opencti_lookup,
        shodan_lookup=shodan_lookup,
        positive_ttl=bounded_int(
            "ENRICHER_POSITIVE_TTL", os.environ.get("ENRICHER_POSITIVE_TTL", "86400"), 60, 604800
        ),
        negative_ttl=bounded_int(
            "ENRICHER_NEGATIVE_TTL", os.environ.get("ENRICHER_NEGATIVE_TTL", "3600"), 60, 86400
        ),
        max_observables=bounded_int(
            "ENRICHER_MAX_OBSERVABLES", os.environ.get("ENRICHER_MAX_OBSERVABLES", "3"), 1, 10
        ),
        max_cache_rows=bounded_int(
            "ENRICHER_MAX_CACHE_ROWS",
            os.environ.get("ENRICHER_MAX_CACHE_ROWS", str(DEFAULT_MAX_CACHE_ROWS)),
            1,
            100_000,
        ),
        max_cache_bytes=bounded_int(
            "ENRICHER_MAX_CACHE_BYTES",
            os.environ.get("ENRICHER_MAX_CACHE_BYTES", str(DEFAULT_MAX_CACHE_BYTES)),
            1024 * 1024,
            1024 * 1024 * 1024,
        ),
    )
    server = BoundedThreadingHTTPServer(
        (listen_host, bounded_int("ENRICHER_LISTEN_PORT", os.environ.get("ENRICHER_LISTEN_PORT", "8780"), 1, 65535)),
        EnrichmentHandler,
        allowed_sources=allowed_sources,
        max_connections=bounded_int(
            "ENRICHER_MAX_CONNECTIONS", os.environ.get("ENRICHER_MAX_CONNECTIONS", "16"), 1, 128
        ),
        read_timeout=bounded_float(
            "ENRICHER_READ_TIMEOUT", os.environ.get("ENRICHER_READ_TIMEOUT", "5"), 0.1, 30.0
        ),
        connection_deadline=bounded_float(
            "ENRICHER_CONNECTION_DEADLINE", os.environ.get("ENRICHER_CONNECTION_DEADLINE", "15"), 0.5, 60.0
        ),
    )
    server.app = {  # type: ignore[attr-defined]
        "allowed_sources": allowed_sources,
        "token": token,
        "max_body": bounded_int(
            "ENRICHER_MAX_BODY", os.environ.get("ENRICHER_MAX_BODY", str(512 * 1024)), 1024, 1024 * 1024
        ),
        "enricher": enricher,
    }
    print("cti-alert-enricher ready", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
