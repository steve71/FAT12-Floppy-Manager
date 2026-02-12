# -*- mode: python ; coding: utf-8 -*-
import sys

# Determine executable name based on platform
# Windows: "Floppy Manager.exe" (with space)
# Linux/Mac: "Floppy_Manager" (with underscore)
if sys.platform.startswith('win'):
    exe_name = 'Floppy Manager'
else:
    exe_name = 'Floppy_Manager'

a = Analysis(
    ['floppy_manager.py'],
    pathex=[],
    binaries=[],
    datas=[('floppy_icon.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name=exe_name,
    console=False,
    icon='floppy_icon.ico',
)