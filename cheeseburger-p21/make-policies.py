#!/usr/bin/env python3
"""Owner-signed verified-root policies (VROOT01 manifests) for the root image flashed to the phone.

Same manifest format and policy table as DinnerABC's scripts/p12-build-policies.py
(kits/VerifiedRoot/tools/manifest.py), with a fresh owner key.  Nothing here touches the image.

  --image <userdata-root.img> <userdata-root.json> <output directory>
      On the workstation that holds the flashed image: hash its two windows.

  --ipsw-dmgs <OS dmg> <SystemOS dmg> <output directory>
      On macOS without the image: extract the raw disk of each IPSW disk image with hdiutil, the
      way unixnu build userdata writes the windows, and hash that.  The window digests must equal
      FLASHED below (the image on the phone), so the manifests fit the flashed image exactly.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
import plistlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

FRAMEWORK = Path(os.environ['P21_FRAMEWORK']).resolve()
sys.path.insert(0, str(FRAMEWORK / 'scripts'))
sys.path.insert(0, str(FRAMEWORK / 'kits' / 'VerifiedRoot' / 'tools'))
import manifest  # noqa: E402

# The OS and SystemOS volume identities of the iPad7,1 17.7.11 (21H461) image.
VOLUME_UUID = {
    'OS': '04769D26-2CA0-4825-B443-E2E5F88300F2',
    'SystemOS': '8846FE78-2910-4297-AF97-D59BB6F8FC16',
}
# What is on the phone: run-44736382733/userdata-root.json of the 2026-11-20 build.
FLASHED = {
    'OS': {'size': 6077580800, 'sha256': 'e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2'},
    'SystemOS': {'size': 3303014400, 'sha256': 'b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f'},
}

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--image', nargs=2, metavar=('IMG', 'JSON'))
parser.add_argument('--ipsw-dmgs', nargs=2, metavar=('OS_DMG', 'SYSTEMOS_DMG'))
parser.add_argument('output', type=Path)
args = parser.parse_args()
if bool(args.image) == bool(args.ipsw_dmgs):
    parser.error('choose exactly one of --image or --ipsw-dmgs')
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
keys = out / 'private'
keys.mkdir(mode=0o700, exist_ok=True)
key, public = keys / 'owner.pem', out / 'owner-public.pem'
if not key.exists():
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(key)],
                   check=True, capture_output=True)
subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)], check=True, capture_output=True)


class Window(io.RawIOBase):
    """A byte range of a file."""

    def __init__(self, path, offset, size):
        self.file = path.open('rb', buffering=8 << 20)
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


class Blocks(io.RawIOBase):
    """An iterator of byte strings as a stream."""

    def __init__(self, blocks):
        self.blocks, self.pending = iter(blocks), b''

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            data = self.pending + b''.join(self.blocks)
        else:
            while len(self.pending) < n:
                data = next(self.blocks, None)
                if data is None:
                    break
                self.pending += data
            data, self.pending = self.pending[:n], self.pending[n:]
        return data


def apfs_volume_uuids(dmg):
    """Volume UUIDs of the APFS volumes of an attached disk image, read with diskutil."""
    attached = subprocess.run(['hdiutil', 'attach', '-readonly', '-nomount', '-noverify', '-noautofsck', str(dmg)],
                              check=True, capture_output=True, text=True).stdout
    whole = re.search(r'(/dev/disk\d+)\s', attached)
    assert whole, attached
    try:
        views = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist']))['images']
        found = [x for x in views if Path(x['image-path']).resolve() == dmg.resolve()]
        assert len(found) == 1, found
        uuids = []
        for entity in found[0]['system-entities']:
            if 'dev-entry' not in entity:
                continue
            info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', entity['dev-entry']]))
            if info.get('FilesystemType') == 'apfs' and info.get('VolumeUUID'):
                uuids.append(info['VolumeUUID'].upper())
        return sorted(set(uuids))
    finally:
        subprocess.run(['hdiutil', 'detach', whole.group(1)], check=True, capture_output=True)


policies = []
for name in ('OS', 'SystemOS'):
    dest = out / name
    flashed = FLASHED[name]
    if args.image:
        report = json.loads(Path(args.image[1]).read_text())
        window = next(w for w in report['windows'] if w['name'] == name)
        assert (window['size'], window['sha256']) == (flashed['size'], flashed['sha256']), f'{name}: not the flashed image'
        context = Window(Path(args.image[0]), window['offset'], window['size'])
    else:
        from unixnu import userdata
        dmg = Path(args.ipsw_dmgs[0 if name == 'OS' else 1]).resolve()
        size = userdata.image_size(dmg)
        assert size == flashed['size'], f'{name}: the disk image is {size} bytes, the flashed window {flashed["size"]}'
        uuids = apfs_volume_uuids(dmg)
        assert uuids == [VOLUME_UUID[name]], f'{name}: APFS volume UUIDs {uuids}, expected {VOLUME_UUID[name]}'
        context = contextlib.nullcontext(Blocks(userdata.disk_blocks(dmg, size)))
    with context as stream:
        record = manifest.make(stream, flashed['size'], key, public, VOLUME_UUID[name], 1, dest)
    assert record['image_sha256'] == flashed['sha256'], f'{name}: raw disk digest differs from the flashed window'
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
with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
    for name in ('OS/manifest.bin', 'SystemOS/manifest.bin', 'OS/trusted-key.bin', 'policies.json'):
        archive.write(out / name, name)
digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
(out / 'policies.zip.sha256').write_text(f'{digest}  policies.zip\n')
print('BUNDLE', bundle, bundle.stat().st_size, digest)
