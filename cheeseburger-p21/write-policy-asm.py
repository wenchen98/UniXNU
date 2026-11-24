#!/usr/bin/env python3
"""Write the verified-root policy assembly linked into the board runtime (inputs.S).

Same table as DinnerABC's scripts/p12-build-policies.py: the owner-signed manifests of the two
root windows and the trusted public anchor.

usage: write-policy-asm.py <directory holding the unpacked policies> <output inputs.S>
"""
import json
import sys
from pathlib import Path

policies, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
table = json.loads((policies / 'policies.json').read_text())['policies']
assert [entry['name'] for entry in table] == ['OS', 'SystemOS'], table
lines = ['.section __DATA_CONST,__const', '.balign 8']
for entry in table:
    manifest = policies / entry['manifest']
    assert manifest.stat().st_size == entry['bytes'], manifest
    symbol = '_verified_root_' + entry['name'].lower() + '_manifest'
    lines += ['.balign 8', '.globl ' + symbol, symbol + ':', f'.incbin "{manifest}"']
lines += ['.balign 8', '.globl _verified_root_key', '_verified_root_key:',
          f'.incbin "{policies / "OS/trusted-key.bin"}"', '.balign 8',
          '.globl _verified_root_policies,_verified_root_policy_count', '_verified_root_policies:']
for entry in table:
    lines.append(f'.quad _verified_root_{entry["name"].lower()}_manifest, {entry["bytes"]}')
lines += ['_verified_root_policy_count:', f'.quad {len(table)}']
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text('\n'.join(lines) + '\n')
print(f'wrote {out} with {len(table)} policies: ' + ', '.join(f'{e["name"]}={e["bytes"]}' for e in table))
