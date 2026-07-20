#!/usr/bin/env python3
"""Wazuh custom integration that forwards alerts to the SOC relay."""

from __future__ import annotations

import json
import ipaddress
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


SUMMARY_LOG = Path(os.environ.get("CTI_ENRICHMENT_LOG", "/var/ossec/logs/cti-enrichment.log"))
MAX_ALERT_FILE = 1024 * 1024
MAX_RESPONSE = 1024 * 1024


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect_not_allowed", headers, fp)


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler())
JSON_TOKEN_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'+-.^_`|~")


def read_bounded_bytes(stream: Any, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("response_too_large")
    return data


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


def bounded_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return str(value)[:limit]


def bounded_strings(value: Any, count: int, width: int) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        rendered = bounded_text(item, width)
        if rendered is not None:
            result.append(rendered)
        if len(result) >= count:
            break
    return result


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def bounded_ints(value: Any, count: int) -> list[int]:
    if not isinstance(value, list):
        return []
    result: list[int] = []
    for item in value:
        try:
            parsed = int(item)
        except (TypeError, ValueError, OverflowError):
            continue
        if 1 <= parsed <= 65535 and parsed not in result:
            result.append(parsed)
        if len(result) >= count:
            break
    return result


def safe_int(value: Any, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return minimum
    return max(minimum, min(parsed, maximum))


def strict_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def summarize_errors(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    source = as_dict(value)
    for key in ("opencti", "shodan", "cache"):
        rendered_error = bounded_text(source.get(key), 64)
        if rendered_error is not None:
            result[key] = rendered_error
    return result


def read_alert_file(path: Path, limit: int) -> dict[str, Any]:
    with path.open("rb") as handle:
        return parse_json_object(read_bounded_bytes(handle, limit))


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


def build_payload(alert: dict[str, Any]) -> dict[str, Any]:
    payload = dict(alert)
    payload.setdefault("source", "wazuh")
    return payload


def is_enrichment_summary(alert: dict[str, Any]) -> bool:
    data = as_dict(alert.get("data"))
    rule = as_dict(alert.get("rule"))
    expected_rule_id = os.environ.get("CTI_ENRICHMENT_RULE_ID", "100950")
    return str(rule.get("id") or "") == expected_rule_id and data.get("integration") == "cti_shodan"


def summarize_opencti(value: Any) -> dict[str, Any]:
    source = as_dict(value)
    return {
        "matched": strict_bool(source.get("matched")),
        "match_count": safe_int(source.get("match_count"), 0, 10),
        "max_score": safe_int(source.get("max_score"), 0, 100),
        "types": bounded_strings(source.get("types"), 10, 128),
        "last_updated": bounded_text(source.get("last_updated"), 64),
    }


def summarize_shodan(value: Any) -> dict[str, Any]:
    source = as_dict(value)
    return {
        "found": strict_bool(source.get("found")),
        "organization": bounded_text(source.get("organization"), 256),
        "isp": bounded_text(source.get("isp"), 256),
        "asn": bounded_text(source.get("asn"), 64),
        "country_code": bounded_text(source.get("country_code"), 8),
        "city": bounded_text(source.get("city"), 256),
        "ports": bounded_ints(source.get("ports"), 25),
        "hostnames": bounded_strings(source.get("hostnames"), 10, 255),
        "vulnerabilities": bounded_strings(source.get("vulnerabilities"), 25, 128),
        "tags": bounded_strings(source.get("tags"), 10, 128),
        "last_update": bounded_text(source.get("last_update"), 64),
    }


def summarize_enrichment(value: Any) -> dict[str, Any]:
    source = as_dict(value)
    output_observables: list[dict[str, Any]] = []
    output: dict[str, Any] = {
        "schema": bounded_text(source.get("schema") or "cti-shodan-enrichment/v1", 64),
        "status": bounded_text(source.get("status") or "unavailable", 32),
        "verdict": bounded_text(source.get("verdict") or "context_only", 32),
        "warning": bounded_text(source.get("warning"), 256),
        "reason": bounded_text(source.get("reason"), 128),
        "observables": output_observables,
    }
    observables = as_list(source.get("observables"))
    for raw in observables[:3]:
        if not isinstance(raw, dict):
            continue
        output_observables.append(
            {
                "type": bounded_text(raw.get("type"), 32),
                "value": bounded_text(raw.get("value"), 64),
                "cache_hit": strict_bool(raw.get("cache_hit")),
                "attention": bounded_text(raw.get("attention"), 32),
                "opencti": summarize_opencti(raw.get("opencti")),
                "shodan": summarize_shodan(raw.get("shodan")),
                "errors": summarize_errors(raw.get("errors")),
            }
        )
    return output


def build_summary_event(alert: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    rule = as_dict(alert.get("rule"))
    agent = as_dict(alert.get("agent"))
    triage = as_dict(response.get("triage"))
    return {
        "integration": "cti_shodan",
        "original_rule_id": bounded_text(rule.get("id") or "unknown", 64),
        "original_rule_level": safe_int(rule.get("level"), 0, 16),
        "agent": bounded_text(agent.get("name") or "unknown", 128),
        "triage": {
            "severity": bounded_text(triage.get("severity"), 32),
            "confidence": bounded_text(triage.get("confidence"), 32),
            "alert_summary": bounded_text(triage.get("alert_summary"), 512),
        },
        "cti_enrichment": summarize_enrichment(response.get("cti_enrichment")),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-cti-n8n <alert_file> <api_key_unused> <hook_url>", file=sys.stderr)
        return 2
    alert_path = Path(argv[1])
    max_alert_file = bounded_int(
        "CTI_N8N_MAX_ALERT_FILE", os.environ.get("CTI_N8N_MAX_ALERT_FILE", str(MAX_ALERT_FILE)), 1024, MAX_ALERT_FILE
    )
    try:
        alert = read_alert_file(alert_path, max_alert_file)
    except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return 1
    if is_enrichment_summary(alert):
        return 0
    request = urllib.request.Request(
        validated_http_url("hook_url", argv[3]),
        data=json.dumps(build_payload(alert), separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "wazuh-cti-n8n/1.0"},
        method="POST",
    )
    timeout = bounded_float("CTI_N8N_TIMEOUT", os.environ.get("CTI_N8N_TIMEOUT", "90"), 0.1, 180.0)
    max_response = bounded_int(
        "CTI_N8N_MAX_RESPONSE", os.environ.get("CTI_N8N_MAX_RESPONSE", str(MAX_RESPONSE)), 1024, MAX_RESPONSE
    )
    with NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:
        if response.status < 200 or response.status >= 300:
            return 1
        result = read_bounded_json(response, max_response)
    with SUMMARY_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(build_summary_event(alert, result), separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
