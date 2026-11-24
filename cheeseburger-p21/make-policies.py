#!/usr/bin/env python3
"""Owner-signed verified-root policies for the flashed userdata-root.img.

Same manifest format and policy table as DinnerABC's scripts/p12-build-policies.py
(kits/VerifiedRoot/tools/manifest.py, VROOT01 envelope), generated from the image that is
already on the phone, with a fresh owner key. Nothing here touches the image.

usage: make-policies.py <userdata-root.img> <userdata-root.json> <output directory>
"""
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

FRAMEWORK = Path(os.environ['P21_FRAMEWORK']).resolve()
sys.path.insert(0, str(FRAMEWORK / 'kits' / 'VerifiedRoot' / 'tools'))
import manifest  # noqa: E402

image_path, report_path, out = (Path(a).resolve() for a in sys.argv[1:4])
VOLUME_UUID = {
    'OS': '04769D26-2CA0-4825-B443-E2E5F88300F2',
    'SystemOS': '8846FE78-2910-4297-AF97-D59BB6F8FC16',
}
report = json.loads(report_path.read_text())
assert image_path.stat().st_size == report['image_bytes']
out.mkdir(parents=True, exist_ok=True)
keys = out / 'private'
keys.mkdir(mode=0o700, exist_ok=True)
key, public = keys / 'owner.pem', out / 'owner-public.pem'
if not key.exists():
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(key)], check=True)
subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)], check=True)


class Window(io.RawIOBase):
    def __init__(self, offset, size):
        self.file = image_path.open('rb', buffering=8 << 20)
        self.file.seek(offset)
        self.left = size

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.left
        data = self.file.read(min(n, self.left))
        self.left -= len(data)
        return data

    def close(self):
        self.file.close()
        super().close()


policies = []
for window in report['windows']:
    name = window['name']
    dest = out / name
    with Window(window['offset'], window['size']) as stream:
        record = manifest.make(stream, window['size'], key, public, VOLUME_UUID[name], 1, dest)
    assert record['image_sha256'] == window['sha256'], f"{name}: image digest differs from the flashed root report"
    envelope = (dest / 'manifest.bin').read_bytes()
    assert len(envelope) == 160 + 384 + record['block_count'] * 32
    for scratch in ('hashes.bin', 'header.bin', 'signature.bin'):
        (dest / scratch).unlink(missing_ok=True)
    entry = dict(name=name, manifest=f'{name}/manifest.bin', bytes=len(envelope), volume_uuid=VOLUME_UUID[name],
                 image_sha256=record['image_sha256'], blocks=record['block_count'],
                 envelope_sha384=hashlib.sha384(envelope).hexdigest())
    policies.append(entry)
    print('SIGNED', json.dumps(entry), flush=True)
assert (out / 'OS/trusted-key.bin').read_bytes() == (out / 'SystemOS/trusted-key.bin').read_bytes()
(out / 'policies.json').write_text(json.dumps(dict(policies=policies,
     signature_scope='Owner-signed ordered block hashes of the flashed root windows; not Apple seal verification'),
     indent=2) + '\n')
bundle = out / 'policies.zip'
with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as z:
    for name in ('OS/manifest.bin', 'SystemOS/manifest.bin', 'OS/trusted-key.bin', 'policies.json'):
        z.write(out / name, name)
digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
(out / 'policies.zip.sha256').write_text(f'{digest}  policies.zip\n')
print('BUNDLE', bundle, bundle.stat().st_size, digest)
