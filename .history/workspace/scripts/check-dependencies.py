#!/usr/bin/env python3
"""Check dependency closures, including transitive dependencies, of core crates."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--all-features", "--locked", "--format-version", "1"]))
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
forbidden = {"pcsc", "pcsc-sys", "rusb", "libusb1-sys", "hidapi", "tokio", "async-std",
             "flutter_rust_bridge", "pyo3", "getrandom"}
roots = [pid for pid in metadata["workspace_members"]
         if packages[pid]["name"] not in {"canokey-c", "canokey-python"}]
for root in roots:
    pending, visited = [root], set()
    while pending:
        pid = pending.pop()
        if pid in visited:
            continue
        visited.add(pid)
        name = packages[pid]["name"]
        if name in forbidden:
            raise SystemExit(f"forbidden dependency: {packages[root]['name']} -> {name}")
        pending.extend(nodes[pid]["dependencies"])
print(f"dependency boundaries verified for {len(roots)} core crates")

# Serializer implementations belong to consumers/examples, never the normal
# x509-info dependency closure. Include build edges, but exclude dev-only edges.
x509_root = next(pid for pid in roots if packages[pid]["name"] == "x509-info")
pending, visited = [x509_root], set()
while pending:
    pid = pending.pop()
    if pid in visited:
        continue
    visited.add(pid)
    if packages[pid]["name"] in {"serde_json", "ciborium", "toml"}:
        raise SystemExit(f"serializer leaked into library dependencies: {packages[pid]['name']}")
    pending.extend(dep["pkg"] for dep in nodes[pid]["deps"]
                   if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
print("certificate serializers remain outside normal library dependencies")
