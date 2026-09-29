"""Build a distributable Genmap release.

Usage:
    python build_release.py                 # tests, then a one folder build in dist/Genmap
    python build_release.py --onefile       # single Genmap.exe (slower start, more AV false positives)
    python build_release.py --installer     # also run Inno Setup when ISCC.exe is available
    python build_release.py --skip-tests

The build never includes Nmap or Npcap. Both are separate products with their
own licenses (Nmap Public Source License, Npcap license) that restrict
redistribution; users install them from https://nmap.org and https://npcap.com.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
BUILD = ROOT / "build"
RELEASE = ROOT / "release"
BRANDING = ROOT / "genmap" / "resources" / "branding"
APP_NAME = "Genmap"


def read_version() -> str:
    namespace: dict[str, str] = {}
    source = (ROOT / "genmap" / "__init__.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith("__version__"):
            exec(line, namespace)
    return namespace["__version__"]


def run(command: list[str], **kwargs) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, cwd=ROOT, **kwargs)


def check_environment() -> None:
    if sys.version_info < (3, 13):
        sys.exit(f"Python 3.13 or newer is required, found {platform.python_version()}.")
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit("PyInstaller is not installed. Run: pip install -r requirements-dev.txt")
    if not (BRANDING / "genmap.ico").is_file():
        sys.exit("Icon files are missing. Run: python scripts/generate_icons.py")


def run_tests() -> None:
    env = dict(os.environ, QT_QPA_PLATFORM=os.environ.get("QT_QPA_PLATFORM", "offscreen"))
    run([sys.executable, "-m", "pytest", "-q", "-m", "not integration"], env=env)


def windows_version_file(version: str) -> Path:
    parts = [int(p) if p.isdigit() else 0 for p in version.split(".")][:4]
    parts += [0] * (4 - len(parts))
    numbers = ", ".join(str(p) for p in parts)
    text = f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({numbers}), prodvers=({numbers}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Genmap'),
      StringStruct('FileDescription', 'Genmap desktop workbench for Nmap'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'Genmap'),
      StringStruct('OriginalFilename', 'Genmap.exe'),
      StringStruct('ProductName', 'Genmap'),
      StringStruct('ProductVersion', '{version}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    BUILD.mkdir(parents=True, exist_ok=True)
    path = BUILD / "version_info.txt"
    path.write_text(text, encoding="utf-8")
    return path


def pyinstaller(version: str, onefile: bool) -> Path:
    separator = ";" if sys.platform.startswith("win") else ":"
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        # UPX compressed executables are a common cause of antivirus false positives.
        "--noupx",
        "--name",
        APP_NAME,
        "--icon",
        str(BRANDING / "genmap.ico"),
        "--add-data",
        f"{BRANDING}{separator}genmap/resources/branding",
        "--distpath",
        str(DIST),
        "--workpath",
        str(BUILD / "pyinstaller"),
        "--specpath",
        str(BUILD),
        # Only the Qt modules Genmap uses; keeps the bundle and scan surface small.
        "--exclude-module",
        "tkinter",
        "--exclude-module",
        "PyQt6.QtWebEngineCore",
        "--exclude-module",
        "PyQt6.QtWebEngineWidgets",
        "--exclude-module",
        "PyQt6.QtQml",
        "--exclude-module",
        "PyQt6.QtQuick",
        "--exclude-module",
        "PyQt6.QtMultimedia",
        "--exclude-module",
        "PyQt6.QtBluetooth",
    ]
    if sys.platform.startswith("win"):
        command += ["--version-file", str(windows_version_file(version))]
    command.append("--onefile" if onefile else "--onedir")
    command.append(str(ROOT / "genmap" / "__main__.py"))
    run(command)
    if onefile:
        return DIST / (APP_NAME + (".exe" if sys.platform.startswith("win") else ""))
    return DIST / APP_NAME


def write_notices(target_dir: Path) -> None:
    for name in ("README.md", "INSTALLATION.md", "SECURITY.md", "TROUBLESHOOTING.md"):
        source = ROOT / name
        if source.is_file():
            shutil.copy2(source, target_dir / name)
    (target_dir / "THIRD_PARTY_NOTICES.txt").write_text(
        "Genmap bundles the following components:\n\n"
        "  Python runtime (PSF License)\n"
        "  Qt 6 and PyQt6 (GPL v3 / commercial; see https://www.riverbankcomputing.com/software/pyqt/)\n"
        "  pydantic (MIT)\n"
        "  defusedxml (PSF License)\n\n"
        "Genmap does NOT include Nmap or Npcap. They are separate products by the Nmap Project,\n"
        "licensed under the Nmap Public Source License and the Npcap license respectively.\n"
        "Install them from https://nmap.org/download.html and https://npcap.com/.\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package(output: Path, version: str) -> Path:
    RELEASE.mkdir(exist_ok=True)
    system = {"win32": "windows", "darwin": "macos"}.get(sys.platform, sys.platform)
    arch = platform.machine().lower() or "unknown"
    archive = RELEASE / f"{APP_NAME}-{version}-{system}-{arch}.zip"
    if output.is_dir():
        write_notices(output)
        files = [p for p in output.rglob("*") if p.is_file()]
        base = output.parent
    else:
        notices = BUILD / "notices"
        notices.mkdir(parents=True, exist_ok=True)
        write_notices(notices)
        files = [output] + [p for p in notices.iterdir() if p.is_file()]
        base = None
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for file in files:
            arcname = file.relative_to(base) if base else Path(APP_NAME) / file.name
            bundle.write(file, arcname)
    checksum = sha256(archive)
    (archive.parent / (archive.name + ".sha256")).write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    return archive


def build_installer(version: str) -> None:
    iscc = shutil.which("ISCC") or shutil.which("iscc")
    candidates = [Path(os.environ.get("ProgramFiles(x86)", "")) / "Inno Setup 6" / "ISCC.exe"]
    if not iscc:
        iscc = next((str(p) for p in candidates if p.is_file()), None)
    if not iscc:
        print("Inno Setup (ISCC.exe) was not found; skipping the installer. Get it from https://jrsoftware.org/isinfo.php")
        return
    run([iscc, f"/DAppVersion={version}", f"/DSourceDir={DIST / APP_NAME}", f"/DOutputDir={RELEASE}", str(ROOT / "installer" / "genmap.iss")])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--onefile", action="store_true", help="build a single executable instead of a folder")
    parser.add_argument("--skip-tests", action="store_true", help="do not run the test suite first")
    parser.add_argument("--installer", action="store_true", help="build the Windows installer with Inno Setup")
    parser.add_argument("--keep-build", action="store_true", help="keep intermediate build files")
    args = parser.parse_args()

    check_environment()
    version = read_version()
    print(f"Building {APP_NAME} {version} on {platform.system()} {platform.machine()}")
    if not args.skip_tests:
        run_tests()
    for folder in (DIST / APP_NAME,):
        if folder.exists():
            shutil.rmtree(folder)
    output = pyinstaller(version, args.onefile)
    if not output.exists():
        sys.exit(f"PyInstaller finished but {output} was not created.")
    archive = package(output, version)
    print(f"Build output: {output}")
    print(f"Release archive: {archive}")
    if args.installer:
        if not sys.platform.startswith("win"):
            print("The installer can only be built on Windows.")
        elif args.onefile:
            print("The installer packages the one folder build; rerun without --onefile.")
        else:
            build_installer(version)
    if not args.keep_build and (BUILD / "pyinstaller").exists():
        shutil.rmtree(BUILD / "pyinstaller", ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
