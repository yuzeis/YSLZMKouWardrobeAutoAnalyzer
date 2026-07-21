# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files


project_root = Path(SPECPATH).parent
product_name = "YSLZMKouWardrobeAutoAnalyzer-ver1.0-beta1-windows-x64"

datas = collect_data_files("scapy", includes=["VERSION"])
datas += [
    (str(project_root / "DatAnDict"), "DatAnDict"),
    (str(project_root / "Docs"), "Docs"),
    (str(project_root / "LICENSE"), "."),
    (str(project_root / "CHANGELOG.md"), "."),
    (str(project_root / "RELEASE_NOTES.md"), "."),
    (str(project_root / "THIRD_PARTY_NOTICES.md"), "."),
    (str(project_root / "YKARequirementsLock.txt"), "."),
    (str(project_root / "YKARequirementsBuildLock.txt"), "."),
]

hiddenimports = [
    "qrcode.image.base",
    "qrcode.image.pil",
    "scapy",
    "scapy.all",
    "scapy.arch",
    "scapy.arch.libpcap",
    "scapy.arch.windows",
    "scapy.arch.windows.native",
    "scapy.config",
    "scapy.interfaces",
    "scapy.layers.all",
    "scapy.layers.inet",
    "scapy.layers.inet6",
    "scapy.layers.l2",
    "scapy.libs.winpcapy",
    "scapy.packet",
    "scapy.sendrecv",
    "scapy.supersocket",
    "scapy.utils",
]

a = Analysis(
    [str(project_root / "YKAApp.py")],
    pathex=[str(project_root)],
    binaries=[],
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
    name=product_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(project_root / "Packaging" / "YKAWindowsVersionInfo.txt"),
)
