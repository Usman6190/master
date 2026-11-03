# PyInstaller spec — build with:  pyinstaller installer/audit_bot.spec --noconfirm
# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
hidden = collect_submodules("scanners") + collect_submodules("dns") + ["reportlab.graphics.barcode.common"]

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "assets"), "assets")],
    hiddenimports=hidden,
    excludes=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore", "tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="CreativeStallAuditBot", console=False,
          icon=str(ROOT / "assets" / "app.ico"), version=None)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="CreativeStallAuditBot")
