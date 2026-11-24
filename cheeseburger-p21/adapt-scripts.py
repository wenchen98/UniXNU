#!/usr/bin/env python3
"""Derive the build scripts of this directory from DinnerABC's tracked ones with minimal, mechanical changes.

Each substitution must match exactly once, so a drift of the upstream source is an error instead of a silent
mis-adaptation. Run from this directory:  python3 adapt-scripts.py <device checkout at the pinned commit>
"""
import subprocess
import sys
from pathlib import Path

device = Path(sys.argv[1]).resolve()
here = Path(__file__).resolve().parent


def adapt(source, target, substitutions):
    text = (device / source).read_text()
    for old, new in substitutions:
        if text.count(old) != 1:
            raise SystemExit(f'{source}: expected exactly one occurrence of {old!r}, found {text.count(old)}')
        text = text.replace(old, new)
    (here / 'cheeseburger-p21' / target).write_text(text)
    print('wrote', target)


adapt('scripts/p21-build-board-runtime.py', 'p21-build-board-runtime.py', [
    ("U=R/'.work/p21-official-framework'",
     "U=Path(os.environ['P21_FRAMEWORK']).resolve()"),
    ("T=R/'out/p21/official-adaptation/resolved/cheeseburger/ipados-17.7.11-21H461/cheeseburger/tree'",
     "T=Path(os.environ['P21_TREE']).resolve()"),
    ("O=R/'out/p21/official-adaptation/runtime-build'",
     "O=Path(os.environ['P21_RUNTIME_OUT']).resolve()"),
    ("ENV=dict(os.environ,DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',",
     "ENV=dict(os.environ,DEVELOPER_DIR=os.environ.get('DEVELOPER_DIR') or '/Applications/Xcode.app/Contents/Developer',"),
    ("for p in (R/'out/p11/storage-abi/include/IOKit/storage').glob('*.h')",
     "for p in (T/'build/storage-abi/include/IOKit/storage').glob('*.h')"),
    ("commands.append({'source':str(src.relative_to(R)),",
     "commands.append({'source':str(src.relative_to(R)) if src.is_relative_to(R) else str(src),"),
    ("run(['/opt/homebrew/opt/llvm/bin/llvm-objcopy',",
     "run([shutil.which('llvm-objcopy'),"),
    ("subprocess.run([sys.executable,R/'scripts/p21-select-official-log-reports.py',*compiled],check=True)",
     "subprocess.run([sys.executable,str(Path(os.environ['P21_BUILD_DIR']).resolve()/'p21-select-official-log-reports.py'),*map(str,compiled)],check=True)"),
    ("policy=R/'out/p12/policies/inputs.S'",
     "policy=Path(os.environ['P21_POLICY_INPUTS']).resolve()"),
])

adapt('scripts/p21-select-official-log-reports.py', 'p21-select-official-log-reports.py', [
    ("import json,re,subprocess,hashlib,sys",
     "import json,re,subprocess,hashlib,sys,shutil,os"),
    ("output=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-nm',",
     "output=subprocess.check_output([shutil.which('llvm-nm'),"),
    ("O=R/'out/p21/official-adaptation/runtime-build'",
     "O=Path(os.environ['P21_RUNTIME_OUT']).resolve()"),
])

for name, origin in (('p21-build-board-runtime.py', 'scripts/p21-build-board-runtime.py'),
                     ('p21-select-official-log-reports.py', 'scripts/p21-select-official-log-reports.py')):
    diff = subprocess.run(['git', '-C', str(device), 'diff', '--no-index', '--stat', str(device / origin), str(here / name)],
                          capture_output=True, text=True).stdout
    print(diff.strip().splitlines()[-1] if diff.strip() else f'{name}: identical')
