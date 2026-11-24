#!/usr/bin/env python3
"""Offline SmartScreen HAR inventory. Does not send requests or infer trust."""
import argparse
import base64
import hashlib
import json
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

DECISION_KEYS = {
    "determination", "verdict", "action", "reputation", "category",
    "confidence", "ttl", "status", "reason", "level",
}
SAFE_VALUES = {
    "allow", "allowed", "block", "blocked", "warn", "warning", "unknown",
    "clean", "safe", "unsafe", "malicious", "phishing", "pending", "none",
    "anywhere", "storeonly", "error", "success", "unrecognized",
}
UI_ACTIONS = {"allowed", "warned", "blocked", "not_observed"}


def digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def endpoint(url):
    """Classify only the interfaces identified in the local source material."""
    if not isinstance(url, str):
        return None
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.port not in (None, 443):
            return None
        host, path = parsed.hostname, parsed.path
    except (TypeError, ValueError):
        return None
    if host == "checkappexec.microsoft.com":
        if re.fullmatch(r"/windows/shell/service/beforeExecute/\d+", path):
            return {"host": host, "path": path, "surface": "shell_execution"}
        return None
    if host not in {"nav-edge.smartscreen.microsoft.com", "app-edge.smartscreen.microsoft.com"}:
        return None
    match = re.fullmatch(
        r"/api/browser/edge/(navigate|navigationcomplete|download|downloadcomplete|actions|telemetry|ssrs)/(\d+)(/sync)?",
        path,
    )
    if not match:
        return None
    kind = match.group(1)
    surface = ("navigation" if kind in {"navigate", "navigationcomplete"}
               else "download" if kind in {"download", "downloadcomplete"}
               else "telemetry")
    return {"host": host, "path": path, "surface": surface}


def json_body(container):
    """Return content and availability; HAR response content may be base64."""
    text = container.get("text") if isinstance(container, dict) else None
    if not isinstance(text, str) or not text:
        return None, "not_captured", None
    try:
        raw = (base64.b64decode(text, validate=True)
               if container.get("encoding") == "base64" else text.encode("utf-8"))
    except (ValueError, TypeError):
        return None, "invalid_base64", None
    try:
        return json.loads(raw), "json", digest(raw)
    except (ValueError, UnicodeError):
        return None, "not_json", digest(raw)


def scalar(value):
    """Only expose primitive decision values, never arbitrary response strings."""
    if isinstance(value, float) and not math.isfinite(value):
        return {"type": "nonfinite_float", "value_omitted": True}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str) and value.lower() in SAFE_VALUES:
        return value
    return {"type": type(value).__name__, "value_omitted": True}


def candidate_fields(value, depth=0):
    """Preserve raw candidate values without assigning undocumented semantics."""
    result = []
    if depth > 8:
        return result
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in DECISION_KEYS:
                result.append({"key": key.lower(), "depth": depth, "raw_value": scalar(child)})
            result.extend(candidate_fields(child, depth + 1))
            if len(result) >= 100:
                break
    elif isinstance(value, list):
        for child in value[:100]:
            result.extend(candidate_fields(child, depth + 1))
            if len(result) >= 100:
                break
    return result[:100]


def path_get(value, *parts):
    for part in parts:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def file_hash(request):
    """Request-provided identity, not independent verification of file bytes."""
    value = path_get(request, "file", "hash")
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()
    try:
        raw = base64.b64decode(value, validate=True)
        return raw.hex() if len(raw) == 32 else None
    except ValueError:
        return None


def request_context(request):
    result = {"file_sha256_from_request": file_hash(request), "request_policy": {}}
    uri = path_get(request, "destination", "uri")
    if isinstance(uri, str):
        result["destination_uri_sha256"] = digest(uri)
    correlation = path_get(request, "correlationId")
    if isinstance(correlation, str):
        result["correlation_id_sha256"] = digest(correlation)
    for owner, name in [("user", "uriReputation"), ("device", "appReputation"), ("device", "appControl")]:
        policy = path_get(request, "config", owner, name)
        if isinstance(policy, dict):
            result["request_policy"][name] = {
                k: scalar(policy[k]) for k in ("level", "enforcedByPolicy") if k in policy
            }
    return result


def observations_by_entry(data):
    if not isinstance(data, dict) or not isinstance(data.get("observations", []), list):
        raise ValueError("Observations input must be an object with an observations array")
    result = {}
    for item in data.get("observations", []):
        if not isinstance(item, dict):
            raise ValueError("Each observation must be an object")
        index = item.get("entry_index")
        if type(index) is not int or index < 0 or index in result:
            raise ValueError("Observation entry_index must be unique and nonnegative")
        action = item.get("ui_action", "not_observed")
        if not isinstance(action, str) or action not in UI_ACTIONS:
            raise ValueError("Unrecognized ui_action")
        policy_confirmed = item.get("effective_policy_confirmed", False)
        if type(policy_confirmed) is not bool:
            raise ValueError("effective_policy_confirmed must be a boolean")
        # User observations are evidence annotations, never protocol-derived verdicts.
        result[index] = {"ui_action": action, "effective_policy_confirmed": policy_confirmed}
    return result


def audit(har, observations=None):
    entries = path_get(har, "log", "entries")
    if not isinstance(entries, list):
        raise ValueError("Input must be a HAR object containing log.entries")
    observation_map = observations_by_entry({} if observations is None else observations)
    records = []
    seen = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        target = endpoint(request.get("url")) if isinstance(request, dict) else None
        if target is None:
            continue
        seen.add(index)
        response = entry.get("response", {})
        if not isinstance(response, dict):
            response = {}
        req_json, req_state, _ = json_body(request.get("postData", {}))
        resp_json, resp_state, response_hash = json_body(response.get("content", {}))
        observation = observation_map.get(index, {
            "ui_action": "not_observed", "effective_policy_confirmed": False,
        })
        gaps = []
        if req_state != "json":
            gaps.append("request_body_unavailable")
        if resp_state != "json":
            gaps.append("response_body_unavailable")
        if observation["ui_action"] == "not_observed":
            gaps.append("client_enforcement_not_observed")
        if not observation["effective_policy_confirmed"]:
            gaps.append("effective_policy_not_confirmed")
        status = response.get("status")
        records.append({
            "entry_index": index, **target,
            "http_status": status if type(status) is int else None,
            "request_body_state": req_state, "response_body_state": resp_state,
            "response_body_sha256": response_hash,
            **request_context(req_json),
            "response_candidate_fields": candidate_fields(resp_json),
            "cloud_verdict": "not_interpreted",
            "observation": observation, "evidence_gaps": gaps,
        })
    unmatched = sorted(set(observation_map) - seen)
    if unmatched:
        raise ValueError("Observations refer to missing/non-SmartScreen HAR entries: " + str(unmatched))
    return {
        "schema_version": 1, "mode": "offline_capture_review",
        "total_har_entries": len(entries), "smartscreen_entries": len(records),
        "interpretation": "HTTP success, cloud reputation, and client enforcement are separate observations. No vulnerability is inferred.",
        "records": records,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("har", type=Path)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    try:
        har = json.loads(args.har.read_text(encoding="utf-8-sig"))
        observations = (json.loads(args.observations.read_text(encoding="utf-8-sig"))
                        if args.observations else None)
        report = audit(har, observations)
        result = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(result, encoding="utf-8")
        else:
            print(result, end="")
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
