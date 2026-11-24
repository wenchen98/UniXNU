#!/usr/bin/env python3
"""Build the DinnerABC P21 cheeseburger kernel with the official framework API.

Derived from DinnerABC/UniXNU-cheeseburger scripts/p21-compile-fb-qup3.py (a42377d): the same
resolve -> assemble -> patch -> archives -> XNU sequence, with the maintainer's untracked local
inputs replaced by the environment cheeseburger-p21.yml sets.  Nothing is prelinked or packaged
here, and the board guard (example = true) stays: this driver only compiles.

  P21_FRAMEWORK    UniXNU framework checkout (16e592ab, with the device's patches/framework applied)
  P21_DEVICE       DinnerABC/UniXNU-cheeseburger checkout
  P21_OUT          output root (feeds, state.json and <board>/<os>/<config>/)
  P21_BUILD_DIR    directory holding p21-build-board-runtime.py and p21-select-official-log-reports.py
  P21_POLICY_INPUTS   verified-root policy assembly (inputs.S) linked into the board runtime
  JOBS             parallel jobs (default 6)
"""
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path

FRAMEWORK = Path(os.environ['P21_FRAMEWORK']).resolve()
DEVICE = Path(os.environ['P21_DEVICE']).resolve()
OUT = Path(os.environ['P21_OUT']).resolve()
BUILD_DIR = Path(os.environ['P21_BUILD_DIR']).resolve()
JOBS = os.environ.get('JOBS', '6')

sys.path.insert(0, str(FRAMEWORK / 'scripts'))
from unixnu.cli import REFERENCES, parser  # noqa: E402
from unixnu.config import Context  # noqa: E402
from unixnu import feeds, kernel, patches, tree  # noqa: E402

os.environ.setdefault('DEVELOPER_DIR', '/Applications/Xcode.app/Contents/Developer')
args = parser().parse_args(['tree', '-D', str(DEVICE), '--out', str(OUT), '-j', JOBS])
c = Context(args)
modules = feeds.resolve(c)
c.modules = modules
wanted = set(REFERENCES['kernel'])
feeds.fetch(c, modules, only={m.name for m in modules.values()
                              if m.origin == 'git' and (m.kind != 'refer' or m.name in wanted)})
tree.assemble(c, modules)
patches.prepare(c, modules)

os.environ['P21_BOARD_ROOT'] = str(DEVICE)
os.environ['P21_TREE'] = str(c.tree)
os.environ['P21_RUNTIME_OUT'] = str(c.work / 'runtime-build')
shutil.copy2(BUILD_DIR / 'p21-build-board-runtime.py', c.tree / 'scripts/p21-build-board-runtime.py')
assert c.example, 'Image pipeline remains guarded until firmware/ABI qualification'

start = time.time()
kernel.build(c, modules)
built = c.tree / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf'
assert built.is_file(), built
native = c.work / 'native/kernel.macho'
native.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(built, native)
report = {'result': 'OFFICIAL_KERNEL_SOURCE_BUILD_PASS', 'duration_seconds': round(time.time() - start, 1),
          'board_guard_retained': c.example, 'prelinked': False, 'booted': False, 'phone_operations': [],
          'tree': str(c.tree), 'kernel_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
          'kernel_bytes': native.stat().st_size}
(c.work / 'kernel-source-build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
