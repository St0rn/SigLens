# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all
from pathlib import Path
import sys

datas = [
    ('src/siglens/templates', 'siglens/templates'),
    ('schemas', 'schemas'),
]
binaries = []
hiddenimports = []

# Some managed Python distributions keep Tcl/Tk beside libpython rather than in
# a system loader path. Include those runtime libraries when present; standard
# Windows and python.org installations continue to rely on PyInstaller's hook.
runtime_lib = Path(sys.base_prefix) / 'lib'
for runtime_name in ('libtcl9.0.so', 'libtcl9tk9.0.so'):
    runtime_path = runtime_lib / runtime_name
    if runtime_path.is_file():
        binaries.append((str(runtime_path), '.'))

tmp_ret = collect_all('yara')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['siglens_launcher.py'],
    pathex=['src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SigLens',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
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
