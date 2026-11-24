#!/usr/bin/env python3
"""Prelink the native kernel against the original kernelcache with the official XnuPrelink tool.

The parameters are DinnerABC's tracked candidate recipe
(rebuild/ipados-up1/touch-scripts/prelink.py): the P19 slide, which keeps the absolute original
bindings of package/BoardRuntime/*-original-bindings.S valid, and its 13 root kexts (the tool adds
their dependency closure).

usage: prelink.py <native kernel.macho> <kernelcache.macho> <output directory>
"""
import hashlib
import os
import subprocess
import sys
from pathlib import Path

FRAMEWORK = Path(os.environ['P21_FRAMEWORK']).resolve()
native, cache, out = (Path(argument).resolve() for argument in sys.argv[1:4])

KERNELCACHE_SHA256 = 'f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7'
SLIDE = -0xc2d000
EARLY_SECURITY_INIT = 'com.apple.driver.AppleMobileFileIntegrity=0xfffffff005ab4ae0'
ROOTS = [
    'com.apple.security.AppleImage4',
    'com.apple.driver.AppleMobileFileIntegrity',
    'com.apple.kext.CoreTrust',
    'com.apple.kec.pthread',
    'com.apple.filesystems.apfs',
    'com.apple.filesystems.hfs.kext',
    'com.apple.AppleFSCompression.AppleFSCompressionTypeZlib',
    'com.apple.security.sandbox',
    'com.apple.kext.AppleMatch',
    'com.apple.iokit.IOSurface',
    'com.apple.iokit.IOMobileGraphicsFamily',
    'com.apple.iokit.IOHIDFamily',
    'com.apple.iokit.IOHIDEventDriver',
]

assert hashlib.sha256(cache.read_bytes()).hexdigest() == KERNELCACHE_SHA256, 'not the 21H461 kernelcache'
sys.path.insert(0, str(FRAMEWORK / 'kits/XnuPrelink'))
import native_prelink as np  # noqa: E402

native_image, cache_image = np.macho(native.read_bytes()), np.macho(cache.read_bytes())
# Derive the layout from complete coalesced ranges, including holes, not device addresses.
old_end = max(x['va'] + x['size'] for x in cache_image['segments']
              if x['name'] in ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PLK_DATA_CONST', '__PRELINK_DATA'])
native_begin = min(x['va'] for x in native_image['segments'] if x['size'])
assert old_end + SLIDE + 4096 <= native_begin, 'Retain the P19 absolute storage bindings; fail on overlap'

out.mkdir(parents=True, exist_ok=True)
command = [sys.executable, FRAMEWORK / 'kits/XnuPrelink/emit_prelink.py', '--kernel', native,
           '--prelinked', cache, f'--slide={hex(SLIDE)}', '--output', out / 'kernel.macho']
for root in ROOTS:
    command += ['--root', root]
command += ['--early-security-init', EARLY_SECURITY_INIT]
subprocess.run([str(part) for part in command], check=True, cwd=FRAMEWORK)
result = out / 'kernel.macho'
print(f'prelinked {result} {result.stat().st_size} bytes sha256 {hashlib.sha256(result.read_bytes()).hexdigest()}')
