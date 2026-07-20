import contextlib
import importlib.util
import io
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class FakeJsonResponse(io.BytesIO):
    def __init__(self, body: bytes, content_type: str = "application/json"):
        super().__init__(body)
        self.headers = {"Content-Type": content_type}


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CTIAlertIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.enricher = load_module("cti_alert_enricher", "automation/cti_alert_enricher.py")
        cls.relay = load_module("enriching_alert_relay", "automation/enriching_alert_relay.py")
        cls.wazuh = load_module("custom_cti_n8n", "automation/custom_cti_n8n.py")

    def test_systemd_credential_is_preferred_over_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "opencti_token"
            credential.write_text("credential-value\n", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"CREDENTIALS_DIRECTORY": directory, "OPENCTI_TOKEN": "environment-value"},
                clear=False,
            ):
                self.assertEqual(
                    self.enricher.read_runtime_secret("opencti_token", "OPENCTI_TOKEN"),
                    "credential-value",
                )

    def test_broker_handler_enforces_source_authentication_and_body_limit(self):
        server = self.enricher.ThreadingHTTPServer(("127.0.0.1", 0), self.enricher.EnrichmentHandler)
        server.app = {
            "allowed_sources": set(),
            "token": "placeholder-broker-token",
            "max_body": 64,
            "enricher": mock.Mock(enrich_alert=lambda payload: {"status": "enriched"}),
        }
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/v1/enrich"
        try:
            request = urllib.request.Request(url, data=b"{}", method="POST")
            with self.assertRaisesRegex(urllib.error.HTTPError, "403"):
                urllib.request.urlopen(request, timeout=2)
            server.app["allowed_sources"] = {"127.0.0.1"}
            with self.assertRaisesRegex(urllib.error.HTTPError, "403"):
                urllib.request.urlopen(request, timeout=2)
            oversized = urllib.request.Request(
                url,
                data=b"x" * 65,
                headers={"Authorization": "Bearer placeholder-broker-token"},
                method="POST",
            )
            with self.assertRaisesRegex(urllib.error.HTTPError, "413"):
                urllib.request.urlopen(oversized, timeout=2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_relay_handler_denies_source_and_unknown_route_before_upstream(self):
        server = self.relay.ThreadingHTTPServer(("127.0.0.1", 0), self.relay.RelayHandler)
        server.app = {
            "allowed_source": "192.0.2.1",
            "splunk_token": "expected-route-token",
            "wazuh_token": None,
        }
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            request = urllib.request.Request(base + "/splunk/placeholder", data=b"{}", method="POST")
            with self.assertRaisesRegex(urllib.error.HTTPError, "403"):
                urllib.request.urlopen(request, timeout=2)
            server.app["allowed_source"] = "127.0.0.1"
            with self.assertRaisesRegex(urllib.error.HTTPError, "404"):
                urllib.request.urlopen(request, timeout=2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_extracts_unique_public_ipv4s_and_caps_work(self):
        private_fixture = ".".join(("10", "1", "2", "3"))
        payload = {
            "srcip": "8.8.8.8",
            "nested": [
                "connection 1.1.1.1:443",
                f"private {private_fixture}",
                "duplicate 8.8.8.8",
                "third 9.9.9.9 and fourth 208.67.222.222",
            ],
        }
        self.assertEqual(
            self.enricher.extract_public_ipv4s(payload, limit=3),
            ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
        )

    def test_rejects_multicast_and_other_non_unicast_ipv4s(self):
        multicast_one = ".".join(("224", "0", "0", "1"))
        multicast_two = ".".join(("239", "255", "255", "250"))
        payload = {"values": [multicast_one, multicast_two, "0.0.0.0", "127.0.0.1", "8.8.8.8"]}
        self.assertEqual(self.enricher.extract_public_ipv4s(payload), ["8.8.8.8"])

    def test_authenticated_http_redirects_are_denied(self):
        request = urllib.request.Request(
            "https://example.invalid/source",
            headers={"Authorization": "Bearer placeholder-value"},
        )
        for module in (self.enricher, self.relay, self.wazuh):
            with self.subTest(module=module.__name__):
                with self.assertRaises(urllib.error.HTTPError):
                    module.NoRedirectHandler().redirect_request(
                        request,
                        None,
                        302,
                        "redirect",
                        {},
                        "https://other.invalid/target",
                    )

    def test_outbound_absolute_deadline_stops_drip_fed_response(self):
        class DripHandler(self.enricher.BaseHTTPRequestHandler):
            def do_GET(inner_self):
                inner_self.send_response(200)
                inner_self.send_header("Content-Type", "application/json")
                inner_self.send_header("Content-Length", "100")
                inner_self.end_headers()
                for _ in range(100):
                    try:
                        inner_self.wfile.write(b" ")
                        inner_self.wfile.flush()
                    except OSError:
                        break
                    time.sleep(0.03)

            def log_message(inner_self, format, *args):
                return

        server = self.enricher.ThreadingHTTPServer(("127.0.0.1", 0), DripHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_address[1]}/drip"
        try:
            for module in (self.enricher, self.relay):
                started = time.monotonic()
                with self.assertRaises((OSError, ValueError)):
                    with module.build_deadline_opener(0.2).open(url, timeout=1.0) as response:
                        module.read_bounded_bytes(response, 1024)
                self.assertLess(time.monotonic() - started, 0.8)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_bounded_json_reader_rejects_oversized_response(self):
        for module in (self.enricher, self.relay):
            response = FakeJsonResponse(b'{"value":"' + (b"x" * 128) + b'"}')
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.read_bounded_json(response, 64)

    def test_json_reader_rejects_invalid_json_substring_media_type(self):
        for module in (self.enricher, self.relay, self.wazuh):
            response = FakeJsonResponse(b"{}", "text/notjson")
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.read_bounded_json(response, 64)

    def test_json_reader_rejects_malformed_suffix_types_and_nonfinite_numbers(self):
        invalid_types = ("application/+json", "application/*+json", "application/a/b+json", "application/a b+json")
        for module in (self.enricher, self.relay, self.wazuh):
            for media_type in invalid_types:
                with self.subTest(module=module.__name__, media_type=media_type):
                    with self.assertRaises(ValueError):
                        module.read_bounded_json(FakeJsonResponse(b"{}", media_type), 1024)
            for body in (b'{"value": Infinity}', b'{"value": 1e999}'):
                with self.subTest(module=module.__name__, body=body):
                    with self.assertRaises(ValueError):
                        module.read_bounded_json(FakeJsonResponse(body), 1024)

    def test_json_reader_accepts_application_json_suffix(self):
        for module in (self.enricher, self.relay, self.wazuh):
            response = FakeJsonResponse(b"{}", "application/problem+json; charset=utf-8")
            with self.subTest(module=module.__name__):
                self.assertEqual(module.read_bounded_json(response, 64), {})

    def test_bounded_reader_rejects_truncation(self):
        for module in (self.relay, self.wazuh):
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.read_bounded_bytes(io.BytesIO(b"x" * 65), 64)

    def test_wazuh_alert_file_is_read_through_bounded_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alert.json"
            path.write_bytes(b'{"value":"' + (b"x" * 128) + b'"}')
            with self.assertRaises(ValueError):
                self.wazuh.read_alert_file(path, 64)

    def test_configuration_values_require_safe_ranges(self):
        for module in (self.enricher, self.relay, self.wazuh):
            with self.subTest(module=module.__name__, value="nan"):
                with self.assertRaises(ValueError):
                    module.bounded_float("TEST_TIMEOUT", "nan", 0.1, 120.0)
            with self.subTest(module=module.__name__, value="excessive"):
                with self.assertRaises(ValueError):
                    module.bounded_float("TEST_TIMEOUT", "9999", 0.1, 120.0)
        with self.assertRaises(ValueError):
            self.enricher.bounded_int("TEST_LIMIT", "0", 1, 10)

    def test_listener_and_secret_validation_rejects_incompatible_values(self):
        for module in (self.enricher, self.relay):
            with self.subTest(module=module.__name__, case="ipv6"):
                with self.assertRaises(ValueError):
                    module.validated_ipv4("LISTEN_HOST", "::1")
            with self.subTest(module=module.__name__, case="control"):
                with self.assertRaises(ValueError):
                    module.validated_ascii_secret("TOKEN", "validprefix\ninvalidsuffix")
        with self.assertRaises(ValueError):
            self.relay.validated_ascii_secret("ROUTE", "route/segment-token-value", url_safe=True)

    def test_bounded_http_servers_have_source_gate_timeout_and_worker_limit(self):
        for module, handler in (
            (self.enricher, self.enricher.EnrichmentHandler),
            (self.relay, self.relay.RelayHandler),
        ):
            server = module.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                handler,
                allowed_sources={"127.0.0.1"},
                max_connections=2,
                read_timeout=1.0,
                connection_deadline=2.0,
            )
            try:
                self.assertTrue(server.verify_request(None, ("127.0.0.1", 1)))
                self.assertFalse(server.verify_request(None, ("192.0.2.1", 1)))
                self.assertTrue(server._request_slots.acquire(blocking=False))
                self.assertTrue(server._request_slots.acquire(blocking=False))
                self.assertFalse(server._request_slots.acquire(blocking=False))
                server._request_slots.release()
                server._request_slots.release()
                self.assertEqual(server.read_timeout, 1.0)
            finally:
                server.server_close()

    def test_bounded_http_servers_enforce_deadline_and_source_gate_on_real_sockets(self):
        for module in (self.enricher, self.relay):
            class Handler(module.BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

                def log_message(self, format, *args):
                    return

            server = module.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                Handler,
                allowed_sources={"127.0.0.1"},
                max_connections=1,
                read_timeout=0.15,
                connection_deadline=0.3,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=1) as slow:
                    for byte in b"GET / HT":
                        try:
                            slow.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(0.05)
                    slow.settimeout(1)
                    self.assertEqual(slow.recv(1), b"")
                with socket.create_connection(server.server_address, timeout=1) as healthy:
                    healthy.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    healthy.settimeout(1)
                    self.assertIn(b"200 OK", healthy.recv(1024))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)

            denied_server = module.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                Handler,
                allowed_sources={"192.0.2.1"},
                max_connections=1,
                read_timeout=0.1,
                connection_deadline=0.2,
            )
            denied_thread = threading.Thread(target=denied_server.handle_request, daemon=True)
            denied_thread.start()
            try:
                with socket.create_connection(denied_server.server_address, timeout=1) as denied:
                    denied.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    denied.settimeout(1)
                    self.assertEqual(denied.recv(1), b"")
            finally:
                denied_thread.join(timeout=1)
                denied_server.server_close()

    def test_strict_json_rejects_duplicate_object_keys(self):
        duplicate = b'{"source":"first","source":"second"}'
        for module in (self.enricher, self.relay, self.wazuh):
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.strict_json_loads(duplicate)

    def test_numeric_configuration_and_url_hostnames_use_strict_syntax(self):
        for module in (self.enricher, self.relay, self.wazuh):
            for invalid in ("1_0", "+10", " 10", "10 "):
                with self.subTest(module=module.__name__, integer=invalid):
                    with self.assertRaises(ValueError):
                        module.bounded_int("LIMIT", invalid, 1, 100)
            with self.subTest(module=module.__name__, hostname="percent"):
                with self.assertRaises(ValueError):
                    module.validated_http_url("URL", "https://exa%mple.invalid/path")
            if hasattr(module, "bounded_float"):
                for invalid in ("1_0", "+10", " 10", "1e1"):
                    with self.subTest(module=module.__name__, floating=invalid):
                        with self.assertRaises(ValueError):
                            module.bounded_float("TIMEOUT", invalid, 0.1, 100.0)

    def test_cache_prunes_to_row_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=lambda ip: {"matched": False},
                shodan_lookup=lambda ip: {"found": False},
                max_cache_rows=2,
            )
            for observable in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
                service._enrich_one(observable)
            with contextlib.closing(sqlite3.connect(cache)) as connection:
                count = connection.execute("SELECT COUNT(*) FROM enrichment_cache").fetchone()[0]
        self.assertEqual(count, 2)

    def test_cache_applies_row_and_page_ceiling_at_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            with contextlib.closing(sqlite3.connect(cache)) as connection:
                connection.execute(
                    "CREATE TABLE enrichment_cache "
                    "(observable TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, payload TEXT NOT NULL)"
                )
                connection.executemany(
                    "INSERT INTO enrichment_cache(observable, expires_at, payload) VALUES (?, ?, ?)",
                    [(value, 4_102_444_800, "{}") for value in ("8.8.8.8", "1.1.1.1", "9.9.9.9")],
                )
                connection.commit()
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=lambda ip: {"matched": False},
                shodan_lookup=lambda ip: {"found": False},
                max_cache_rows=2,
                max_cache_bytes=1024 * 1024,
            )
            with contextlib.closing(service._connect()) as connection:
                count = connection.execute("SELECT COUNT(*) FROM enrichment_cache").fetchone()[0]
                page_size = connection.execute("PRAGMA page_size").fetchone()[0]
                max_pages = connection.execute("PRAGMA max_page_count").fetchone()[0]
        self.assertEqual(count, 2)
        self.assertLessEqual(max_pages * page_size, 1024 * 1024)

    def test_oversized_cache_is_disabled_before_sqlite_recovery_work(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            with cache.open("wb") as handle:
                handle.truncate(1024 * 1024 + 1)
            with mock.patch.object(self.enricher.sqlite3, "connect", side_effect=AssertionError("sqlite must not open")):
                service = self.enricher.AlertEnricher(
                    cache_path=cache,
                    opencti_lookup=lambda ip: {"matched": False},
                    shodan_lookup=lambda ip: {"found": False},
                    max_cache_bytes=1024 * 1024,
                )
            self.assertFalse(service.cache_available)
            self.assertEqual(cache.stat().st_size, 1024 * 1024 + 1)

    def test_cache_forces_delete_journal_and_stays_within_physical_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=lambda ip: {},
                shodan_lookup=lambda ip: {},
                max_cache_bytes=1024 * 1024,
                max_cache_rows=1000,
            )
            self.assertTrue(service.cache_available)
            with contextlib.closing(service._connect()) as connection:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "delete")
            payload = {"blob": "x" * 60_000}
            for index in range(100):
                try:
                    service._cache_put(f"8.8.8.{index}", payload, 3600)
                except sqlite3.Error:
                    break
            physical = sum(path.stat().st_size for path in service._cache_files() if path.exists())
            self.assertLessEqual(physical, 1024 * 1024)

    def test_transient_cache_read_failure_is_not_persisted_after_successful_write(self):
        calls = {"opencti": 0}

        def opencti(ip):
            calls["opencti"] += 1
            return {"matched": False, "match_count": 0, "max_score": 0, "types": []}

        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=opencti,
                shodan_lookup=lambda ip: {
                    "found": False,
                    "ports": [],
                    "hostnames": [],
                    "vulnerabilities": [],
                    "tags": [],
                },
            )
            with contextlib.closing(service._connect()) as connection:
                connection.execute(
                    "INSERT OR REPLACE INTO enrichment_cache(observable, expires_at, payload) VALUES (?, ?, ?)",
                    ("8.8.8.8", int(time.time()) + 3600, "{}"),
                )
                connection.commit()
            first = service.enrich_alert({"source_ip": "8.8.8.8"})["observables"][0]
            second = service.enrich_alert({"source_ip": "8.8.8.8"})["observables"][0]
            self.assertEqual(first["errors"].get("cache"), "unavailable")
            self.assertNotIn("cache", second["errors"])
            self.assertTrue(second["cache_hit"])
            self.assertEqual(calls["opencti"], 1)

    def test_corrupt_cache_does_not_prevent_enrichment_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            cache.write_bytes(b"not-a-sqlite-database")
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=lambda ip: {"matched": False},
                shodan_lookup=lambda ip: {"found": False},
            )
            result = service.enrich_alert({"ip": "8.8.8.8"})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["observables"][0]["errors"]["cache"], "unavailable")

    def test_wrong_shape_cached_json_degrades_to_cache_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "cache.db"
            service = self.enricher.AlertEnricher(
                cache_path=cache,
                opencti_lookup=lambda ip: {"matched": False},
                shodan_lookup=lambda ip: {"found": False},
            )
            with contextlib.closing(sqlite3.connect(cache)) as connection:
                connection.execute(
                    "INSERT INTO enrichment_cache(observable, expires_at, payload) VALUES (?, ?, ?)",
                    ("8.8.8.8", 4102444800, "[]"),
                )
                connection.commit()
            result = service.enrich_alert({"ip": "8.8.8.8"})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["observables"][0]["errors"]["cache"], "unavailable")

    def test_skips_alert_without_supported_observable(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.enricher.AlertEnricher(
                cache_path=Path(directory) / "cache.db",
                opencti_lookup=lambda ip: self.fail("OpenCTI should not be called"),
                shodan_lookup=lambda ip: self.fail("Shodan should not be called"),
            )
            result = service.enrich_alert({"srcip": "192.0.2.10", "message": "local-only"})
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["observables"], [])

    def test_positive_result_is_cached(self):
        calls = {"opencti": 0, "shodan": 0}

        def opencti(ip):
            calls["opencti"] += 1
            return {"matched": True, "match_count": 1, "max_score": 70, "types": ["IPv4-Addr"]}

        def shodan(ip):
            calls["shodan"] += 1
            return {"found": True, "organization": "Example", "ports": [53], "vulnerabilities": []}

        with tempfile.TemporaryDirectory() as directory:
            service = self.enricher.AlertEnricher(
                cache_path=Path(directory) / "cache.db",
                opencti_lookup=opencti,
                shodan_lookup=shodan,
                positive_ttl=3600,
            )
            first = service.enrich_alert({"ip": "8.8.8.8"})
            second = service.enrich_alert({"ip": "8.8.8.8"})

        self.assertEqual(calls, {"opencti": 1, "shodan": 1})
        self.assertFalse(first["observables"][0]["cache_hit"])
        self.assertTrue(second["observables"][0]["cache_hit"])
        self.assertEqual(second["observables"][0]["attention"], "review")
        self.assertEqual(second["verdict"], "context_only")

    def test_provider_failure_is_partial_not_fatal(self):
        def opencti(ip):
            raise TimeoutError("OpenCTI timeout")

        with tempfile.TemporaryDirectory() as directory:
            service = self.enricher.AlertEnricher(
                cache_path=Path(directory) / "cache.db",
                opencti_lookup=opencti,
                shodan_lookup=lambda ip: {
                    "found": True,
                    "organization": "Example",
                    "ports": [443],
                    "vulnerabilities": ["CVE-EXAMPLE"],
                },
            )
            result = service.enrich_alert({"ip": "8.8.4.4"})

        self.assertEqual(result["status"], "partial")
        observable = result["observables"][0]
        self.assertEqual(observable["attention"], "elevated")
        self.assertIn("opencti", observable["errors"])
        self.assertTrue(observable["shodan"]["found"])

    def test_relay_attaches_enrichment(self):
        payload = {"rule": {"id": "100001"}}
        result = self.relay.attach_enrichment(
            payload,
            lambda value: {
                "schema": "cti-shodan-enrichment/v1",
                "status": "skipped",
                "verdict": "context_only",
                "warning": "Context only.",
                "reason": "no_supported_public_ipv4",
                "observables": [],
            },
        )
        self.assertEqual(result["cti_enrichment"]["status"], "skipped")
        self.assertNotIn("cti_enrichment", payload)

    def test_actual_broker_result_satisfies_relay_schema_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.enricher.AlertEnricher(
                cache_path=Path(directory) / "cache.db",
                opencti_lookup=lambda ip: {"matched": False, "match_count": 0, "max_score": 0, "types": []},
                shodan_lookup=lambda ip: {
                    "found": False,
                    "ports": [],
                    "hostnames": [],
                    "vulnerabilities": [],
                    "tags": [],
                },
            )
            broker_result = service.enrich_alert({"source_ip": "8.8.8.8"})
            relayed = self.relay.attach_enrichment({"source_ip": "8.8.8.8"}, lambda value: broker_result)
            self.assertEqual(relayed["cti_enrichment"]["schema"], broker_result["schema"])
            self.assertEqual(relayed["cti_enrichment"]["status"], "enriched")

    def test_relay_preserves_existing_enrichment_namespace_and_rejects_malformed_result(self):
        original = {"producer": "upstream", "value": "preserve"}
        payload = {"event": "test", "cti_enrichment": original}
        collision = self.relay.attach_enrichment(payload, lambda value: {})
        self.assertEqual(collision["cti_enrichment"], original)
        self.assertEqual(collision["relay_cti_enrichment"]["status"], "unavailable")
        self.assertEqual(payload["cti_enrichment"], original)

        malformed = self.relay.attach_enrichment({"event": "test"}, lambda value: {"status": "enriched"})
        self.assertEqual(malformed["cti_enrichment"]["status"], "unavailable")
        malformed_observables = self.relay.attach_enrichment(
            {"event": "test"},
            lambda value: {
                "schema": "cti-shodan-enrichment/v1",
                "status": "enriched",
                "verdict": "context_only",
                "observables": ["not-an-object"],
            },
        )
        self.assertEqual(malformed_observables["cti_enrichment"]["status"], "unavailable")
        malformed_fields = {
            "schema": "cti-shodan-enrichment/v1",
            "status": "enriched",
            "verdict": "context_only",
            "observables": [
                {
                    "type": "ipv4",
                    "value": {"nested": "invalid"},
                    "cache_hit": "false",
                    "attention": "review",
                    "opencti": [],
                    "shodan": {},
                    "errors": {},
                }
            ],
        }
        self.assertEqual(
            self.relay.attach_enrichment({"event": "test"}, lambda value: malformed_fields)["cti_enrichment"]["status"],
            "unavailable",
        )
        inconsistent = dict(malformed_fields, status="skipped", observables=[{}])
        self.assertEqual(
            self.relay.attach_enrichment({"event": "test"}, lambda value: inconsistent)["cti_enrichment"]["status"],
            "unavailable",
        )

        for invalid_reason in ({"nested": True}, ["invalid"], 7, "x" * 10_000):
            malformed_reason = {
                "schema": "cti-shodan-enrichment/v1",
                "status": "skipped",
                "verdict": "context_only",
                "warning": "Context only.",
                "reason": invalid_reason,
                "observables": [],
            }
            self.assertFalse(self.relay.valid_enrichment(malformed_reason))
        self.assertFalse(
            self.relay.valid_enrichment(
                {
                    "schema": "cti-shodan-enrichment/v1",
                    "status": "unavailable",
                    "verdict": "context_only",
                    "warning": "Context only.",
                    "reason": "no_supported_public_ipv4",
                    "observables": [],
                }
            )
        )

    def test_relay_fails_open_when_enricher_is_unavailable(self):
        def unavailable(value):
            raise OSError("connection refused")

        result = self.relay.attach_enrichment({"event": "test"}, unavailable)
        self.assertEqual(result["cti_enrichment"]["status"], "unavailable")
        self.assertEqual(result["event"], "test")
        self.assertNotIn("connection refused", json.dumps(result))

    def test_relay_attachment_does_not_deepcopy_nested_alert(self):
        payload: dict[str, object] = {}
        current = payload
        for _ in range(600):
            child: dict[str, object] = {}
            current["child"] = child
            current = child
        result = self.relay.attach_enrichment(
            payload,
            lambda value: {
                "schema": "cti-shodan-enrichment/v1",
                "status": "skipped",
                "verdict": "context_only",
                "warning": "Context only.",
                "reason": "no_supported_public_ipv4",
                "observables": [],
            },
        )
        self.assertEqual(result["cti_enrichment"]["status"], "skipped")

    def test_request_json_rejects_invalid_utf8_and_excessive_depth(self):
        deep: dict[str, object] = {}
        current = deep
        for _ in range(40):
            child: dict[str, object] = {}
            current["child"] = child
            current = child
        deep_body = json.dumps(deep).encode()
        for module in (self.enricher, self.relay):
            with self.subTest(module=module.__name__, case="utf8"):
                with self.assertRaises(ValueError):
                    module.parse_json_object(b"\xff")
            with self.subTest(module=module.__name__, case="depth"):
                with self.assertRaises(ValueError):
                    module.parse_json_object(deep_body)

    def test_url_validation_rejects_out_of_range_port(self):
        for module in (self.enricher, self.relay, self.wazuh):
            with self.subTest(module=module.__name__):
                with self.assertRaises(ValueError):
                    module.validated_http_url("TEST_URL", "https://example.invalid:99999/path")

    def test_relay_log_never_includes_tokenized_request_path(self):
        handler = object.__new__(self.relay.RelayHandler)
        handler.client_address = ("198.51.100.10", 12345)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            handler.log_message('"%s" %s %s', "POST /splunk/do-not-log-this-token HTTP/1.1", "200", "123")
        rendered = output.getvalue()
        self.assertNotIn("do-not-log-this-token", rendered)
        self.assertIn("status=200", rendered)

    def test_wazuh_payload_marks_source_without_losing_alert(self):
        alert = {"rule": {"id": "100001"}, "agent": {"name": "LAB-WIN"}}
        result = self.wazuh.build_payload(alert)
        self.assertEqual(result["source"], "wazuh")
        self.assertEqual(result["rule"]["id"], "100001")
        original_source = self.wazuh.build_payload({"source": "original-producer", "rule": {"id": "100001"}})
        self.assertEqual(original_source["source"], "original-producer")

    def test_wazuh_summary_boolean_fields_require_actual_booleans(self):
        self.assertFalse(self.wazuh.summarize_opencti({"matched": "false"})["matched"])
        self.assertFalse(self.wazuh.summarize_shodan({"found": "false"})["found"])
        response = {
            "cti_enrichment": {
                "observables": [{"cache_hit": "false", "opencti": {"matched": True}, "shodan": {"found": True}}]
            }
        }
        observable = self.wazuh.build_summary_event({"rule": {"id": "1"}}, response)["cti_enrichment"]["observables"][0]
        self.assertFalse(observable["cache_hit"])
        self.assertTrue(observable["opencti"]["matched"])
        self.assertTrue(observable["shodan"]["found"])

    def test_wazuh_summary_event_preserves_enrichment_without_raw_alert(self):
        alert = {"rule": {"id": "100001", "level": 12}, "agent": {"name": "LAB-WIN"}, "full_log": "sensitive"}
        response = {
            "triage": {"severity": "high", "confidence": "medium", "alert_summary": "Review public IP"},
            "cti_enrichment": {
                "schema": "cti-shodan-enrichment/v1",
                "status": "enriched",
                "observables": [{"value": "8.8.8.8", "attention": "review"}],
                "verdict": "context_only",
            },
        }
        result = self.wazuh.build_summary_event(alert, response)
        self.assertEqual(result["integration"], "cti_shodan")
        self.assertEqual(result["original_rule_id"], "100001")
        self.assertEqual(result["cti_enrichment"]["verdict"], "context_only")
        self.assertNotIn("full_log", json.dumps(result))

    def test_wazuh_skips_its_own_summary_events(self):
        trusted = {
            "rule": {"id": "100950"},
            "location": "/var/ossec/logs/cti-enrichment.log",
            "data": {"integration": "cti_shodan"},
        }
        spoofed = {"rule": {"id": "100001"}, "data": {"integration": "cti_shodan"}}
        self.assertTrue(self.wazuh.is_enrichment_summary(trusted))
        self.assertFalse(self.wazuh.is_enrichment_summary(spoofed))
        self.assertFalse(self.wazuh.is_enrichment_summary({"integration": "cti_shodan"}))

    def test_wazuh_summary_is_bounded_and_drops_unknown_provider_fields(self):
        response = {
            "triage": {"alert_summary": "x" * 5000},
            "cti_enrichment": {
                "status": "enriched",
                "verdict": "context_only",
                "observables": [
                    {
                        "value": "8.8.8.8",
                        "attention": "review",
                        "shodan": {"organization": "y" * 5000, "raw_response": "sensitive"},
                    }
                ]
                * 10,
                "unexpected": "sensitive",
            },
        }
        summary = self.wazuh.build_summary_event({"rule": {"id": "1"}}, response)
        rendered = json.dumps(summary)
        self.assertLessEqual(len(summary["triage"]["alert_summary"]), 512)
        self.assertLessEqual(len(summary["cti_enrichment"]["observables"]), 3)
        self.assertNotIn("raw_response", rendered)
        self.assertNotIn("unexpected", rendered)

    def test_wazuh_summary_rejects_nested_values_in_scalar_fields(self):
        nested = {"raw_response": "must-not-appear"}
        response = {
            "triage": {"alert_summary": nested},
            "cti_enrichment": {
                "status": "enriched",
                "observables": [
                    {
                        "value": "8.8.8.8",
                        "shodan": {"organization": nested, "tags": [nested]},
                        "errors": {"shodan": nested},
                    }
                ],
            },
        }
        summary = self.wazuh.build_summary_event({"rule": {"id": "1", "level": nested}}, response)
        rendered = json.dumps(summary)
        self.assertNotIn("raw_response", rendered)
        self.assertNotIn("must-not-appear", rendered)
        self.assertIsInstance(summary["original_rule_level"], int)

    def test_wazuh_summary_handles_nonfinite_integers_and_preserves_known_errors(self):
        alert = {"rule": {"id": "1", "level": float("inf")}}
        response = {"cti_enrichment": {
            "schema": "cti-shodan-enrichment/v1",
            "status": "partial",
            "observables": [{
                "value": "8.8.8.8",
                "shodan": {"ports": [float("inf"), 443]},
                "errors": {"unknown1": "x", "unknown2": "x", "unknown3": "x", "cache": "unavailable"},
            }],
        }}
        result = self.wazuh.build_summary_event(alert, response)
        self.assertEqual(result["original_rule_level"], 0)
        observable = result["cti_enrichment"]["observables"][0]
        self.assertEqual(observable["shodan"]["ports"], [443])
        self.assertEqual(observable["errors"], {"cache": "unavailable"})


if __name__ == "__main__":
    unittest.main()
