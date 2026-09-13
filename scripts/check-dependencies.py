#!/usr/bin/env python3
"""Check that inspection stays independent and CLI dependencies remain optional."""
import json
import subprocess


def metadata(*features):
    result = json.loads(subprocess.check_output([
        'cargo', 'metadata', '--locked', '--format-version', '1', *features]))
    packages = {p['id']: p for p in result['packages']}
    nodes = {n['id']: n for n in result['resolve']['nodes']}
    return result['resolve']['root'], packages, nodes


def closure(root, nodes):
    pending, visited = [root], set()
    while pending:
        package = pending.pop()
        if package in visited:
            continue
        visited.add(package)
        yield package
        pending.extend(dep['pkg'] for dep in nodes[package]['deps']
                       if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']))


root, packages, nodes = metadata('--all-features')
forbidden = {'pcsc', 'pcsc-sys', 'rusb', 'libusb1-sys', 'hidapi', 'tokio',
             'async-std', 'flutter_rust_bridge', 'pyo3', 'getrandom'}
for package in closure(root, nodes):
    name = packages[package]['name']
    if name in forbidden or name.startswith('canokey'):
        raise SystemExit(f'forbidden dependency: {name}')

root, packages, nodes = metadata('--no-default-features', '--features', 'serde')
cli_only = {'clap', 'serde_json', 'ciborium', 'toml', 'uuid', 'schemars',
            'serde_yaml_ng', 'rmp-serde'}
for package in closure(root, nodes):
    if packages[package]['name'] in cli_only:
        raise SystemExit(f'optional dependency leaked into serde library: {packages[package]["name"]}')
print('Independent crate and optional feature boundaries verified')
