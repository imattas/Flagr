# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for Flagr.

Bundles the CLI wrapper + full flagr package into a single binary.
Heavy dependencies (pwntools, scipy, matplotlib, etc.) are NOT bundled —
they must be installed via pip on the target system. The binary handles
launching and self-updating.
"""

import os

block_cipher = None
spec_dir = os.path.dirname(os.path.abspath(SPEC))

# Collect all flagr .py files + templates as data
flagr_root = os.path.join(spec_dir, 'flagr')

datas = [
    (os.path.join(spec_dir, 'VERSION'), '.'),
]

for dirpath, dirnames, filenames in os.walk(flagr_root):
    # Skip __pycache__
    dirnames[:] = [d for d in dirnames if d != '__pycache__']
    for f in filenames:
        if f.endswith(('.py', '.html', '.jinja2', '.j2', '.txt', '.png', '.json')):
            src = os.path.join(dirpath, f)
            rel = os.path.relpath(dirpath, os.path.dirname(flagr_root))
            datas.append((src, rel))

a = Analysis(
    ['flagr/cli.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['flagr', 'flagr.__main__', 'flagr.manager', 'flagr.target',
                   'flagr.unit', 'flagr.monitor', 'flagr.util', 'flagr.repl'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # These are too large to bundle — must be pip-installed
        'scipy', 'matplotlib', 'numpy', 'PIL', 'pillow',
        'pwntools', 'pwn', 'capstone', 'unicorn',
        'paramiko', 'tkinter', 'test',
        'enchant', 'pyenchant',
        'cv2', 'sklearn',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='flagr',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
