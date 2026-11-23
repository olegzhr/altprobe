#!/usr/bin/env python3
"""Validate the canonical YAML and regenerate the committed C++ fallback.

Requires PyYAML for development only; the normal C++ build has no Python step.
Run with --check to verify that the generated file is current without writing.
"""
import argparse
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELDS = {"request.text", "response.text", "request.url", "request.headers",
          "request.host", "request.jwt.alg", "request.jwt.header"}
CONTEXTS = {"corporate_data_context", "ai_provider_usage", "ai_gateway_context", "user_fraud_context"}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("invalid or duplicate YAML mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def mapping(value, keys):
    if not isinstance(value, dict) or set(value) - keys:
        raise ValueError("unknown keys or invalid mapping")


def scalar(value, maximum):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("empty, non-string or oversized scalar")
    return value


def sequence(value, maximum):
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise ValueError("empty or oversized sequence")
    return value


def validate(data):
    mapping(data, {"schema_version", "ruleset_version", "rules"})
    if type(data.get("schema_version")) is not int or data["schema_version"] != 2:
        raise ValueError("schema_version must be 2")
    scalar(data.get("ruleset_version"), 64)
    source = (ROOT / "shared" / "api_guard.cpp").read_text(encoding="utf-8")
    section = source.split("const std::unordered_map<std::string, SignalType>& signalKeys()", 1)[1]
    section = section.split("bool isContext(", 1)[0]
    signals = dict(re.findall(r'\{"([a-z_]+)",\s*(SIG_[A-Z_]+)\}', section))
    ids = set()
    for rule in sequence(data.get("rules"), 128):
        mapping(rule, {"id", "kind", "signal", "fields", "tools", "all", "window", "confidence", "reason"})
        rid = scalar(rule.get("id"), 96)
        if rid in ids:
            raise ValueError("duplicate rule id: " + rid)
        ids.add(rid)
        if rule.get("signal") not in signals or rule.get("kind") not in {"threat", "context"}:
            raise ValueError("unsupported signal or rule kind: " + rid)
        if (rule["kind"] == "context") != (rule["signal"] in CONTEXTS):
            raise ValueError("signal/kind mismatch: " + rid)
        scalar(rule.get("reason"), 256)
        fields = sequence(rule.get("fields"), 7)
        if any(not isinstance(f, str) or f not in FIELDS for f in fields) or len(set(fields)) != len(fields):
            raise ValueError("unknown or duplicate field: " + rid)
        if "tools" in rule:
            for tool in sequence(rule["tools"], 32):
                scalar(tool, 128)
        window = rule.get("window", 160)
        confidence = rule.get("confidence", 80)
        if type(window) is not int or not 16 <= window <= 512:
            raise ValueError("invalid window: " + rid)
        if type(confidence) is not int or not 1 <= confidence <= 100:
            raise ValueError("invalid confidence: " + rid)
        for group in sequence(rule.get("all"), 8):
            for term in sequence(group, 32):
                scalar(term, min(128, window))
                if not term.strip():
                    raise ValueError("whitespace-only term: " + rid)
    return signals


def generate(data, signals):
    q = lambda value: json.dumps(value, ensure_ascii=False)
    strings = lambda values: "{" + ", ".join(q(v) for v in values) + "}"
    lines = ["// Generated from etc/api_guard.yaml; do not edit manually.",
             "// Regenerate with scripts/generate_api_guard_rules.py.",
             "out.version = " + q(data["ruleset_version"]) + ";", "out.rules = {"]
    for rule in data["rules"]:
        groups = "{" + ", ".join("{" + ", ".join("norm(" + q(t) + ")" for t in g) + "}"
                                  for g in rule["all"]) + "}"
        lines.append("    {" + ", ".join((q(rule["id"]), q(rule["kind"]), q(rule["reason"]),
                     signals[rule["signal"]], strings(rule["fields"]), strings(rule.get("tools", [])),
                     groups, str(rule.get("window", 160)), str(rule.get("confidence", 80)))) + "},")
    return "\n".join(lines + ["};", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "etc" / "api_guard.yaml"
    source = path.read_bytes()
    if len(source) > 262144:
        raise ValueError("YAML exceeds size limit")
    data = yaml.load(source.decode("utf-8"), Loader=UniqueLoader)
    generated = generate(data, validate(data))
    target = ROOT / "shared" / "api_guard_rules.inc"
    if args.check:
        if not target.is_file() or target.read_text(encoding="utf-8") != generated:
            raise ValueError("api_guard_rules.inc is stale; run generator without --check")
    else:
        target.write_text(generated, encoding="utf-8", newline="\n")
    print(f'{data["ruleset_version"]}: {len(data["rules"])} validated rules; fallback synchronized')


if __name__ == "__main__":
    try:
        main()
    except (ValueError, yaml.YAMLError, OSError) as error:
        print("API Guard configuration error:", error, file=sys.stderr)
        sys.exit(1)
