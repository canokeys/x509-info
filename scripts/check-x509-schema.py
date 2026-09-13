#!/usr/bin/env python3
"""Validate CLI reports with an independent JSON Schema and YAML implementation."""
import argparse
import copy
import json
from pathlib import Path
import subprocess

import jsonschema
import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path, help="Path to the built x509-info executable")
args = parser.parse_args()
binary = str(args.binary.resolve())
fixtures = Path(__file__).resolve().parent.parent / "crates/x509-info/tests/fixtures"


def run(*arguments):
    return subprocess.check_output([binary, *map(str, arguments)], stdin=subprocess.DEVNULL)


count = 0
for summary in (False, True):
    options = ["--summary"] if summary else []
    schema = json.loads(run("--schema", *options))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for certificate in sorted(fixtures.glob("*.pem")):
        report = json.loads(run(certificate, "--format", "json", *options))
        validator.validate(report)
        line = run(certificate, "--format", "jsonl", *options)
        assert line.count(b"\n") == 1
        assert json.loads(line) == report
        assert yaml.safe_load(run(certificate, "--format", "yaml", *options)) == report
        count += 1

    # Ensure the schema constrains values, rather than merely accepting examples.
    report = json.loads(run(fixtures / "details.pem", "--format", "json", *options))
    for path, value in [
        (["report_version"], 999),
        (["certificate", "version"], "invalid"),
        (["spki_sha256_fingerprint_hex"], False),
        (["certificate", "extensions", 0, "details"], {"kind": "invented_variant"}),
    ]:
        changed = copy.deepcopy(report)
        parent = changed
        for component in path[:-1]:
            parent = parent[component]
        parent[path[-1]] = value
        assert not validator.is_valid(changed), path
    # Exercise report-only shapes absent from the static certificate fixtures.
    for details in [
        {"kind": "fido_aaguid", "value": {"uuid": "00000000-0000-0000-0000-000000000000"}},
        {"kind": "fido_aaguid", "value": {"uuid": "ffffffff-ffff-ffff-ffff-ffffffffffff"}},
        {"kind": "fido_aaguid", "value": {
            "uuid": None, "raw_base64": "AP8=",
            "format_diagnostic": {"issue": "invalid_length", "field": "AAGUID", "expected_bytes": 16}}},
        {"kind": "subject_alternative_name", "value": [{
            "kind": "other_name",
            "value": {"oid": "1.3.6.1.4.1.311.20.2.3", "name": None, "value_der_base64": "oAMMAWE="},
            "decoded_fields": {"kind": "user_principal_name", "value": "a"}}]},
        {"kind": "subject_alternative_name", "value": [{
            "kind": "x400_address", "value": {"constructed": True, "content_base64": ""},
            "decode_diagnostic": {"issue": "unsupported_encoding", "field": "X.400"}}]},
    ]:
        changed = copy.deepcopy(report)
        changed["certificate"]["extensions"][0]["details"] = details
        validator.validate(changed)
    changed["certificate"]["extensions"][0]["details"] = {
        "kind": "fido_aaguid", "value": {"uuid": "not-a-uuid"}}
    assert not validator.is_valid(changed)
    missing = copy.deepcopy(report)
    del missing["certificate"]
    assert not validator.is_valid(missing)
    if not summary:
        for invalid in [[48, 130], "not base64!"]:
            report["certificate"]["der_base64"] = invalid
            assert not validator.is_valid(report)

print(f"schema, YAML and JSON Lines contracts verified for {count} full/summary reports")
