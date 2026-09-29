# Installing Genmap

## Requirements

| Component | Version | Why |
|-----------|---------|-----|
| Windows 10 or 11 (64 bit) | | Primary platform. Linux and macOS work from source. |
| Nmap | 7.x, 7.70 or newer recommended | The scanning engine Genmap drives |
| Npcap | Recent release | Raw packet access on Windows (SYN, UDP, OS detection) |
| Python | 3.13 or newer | Only needed when running from source |

## 1. Install Nmap

Genmap does not include Nmap. The Nmap Public Source License does not allow redistributing it inside another product without a separate agreement, so you install it yourself.

**Windows**

1. Download the latest *Latest stable release self installer* from https://nmap.org/download.html.
2. Run it and keep **Npcap** selected when asked. Accept the Npcap defaults. Leave *Restrict Npcap driver's access to Administrators only* unticked unless you plan to always run Genmap as administrator.
3. The default location is `C:\Program Files (x86)\Nmap\nmap.exe`. Genmap finds it there automatically.

**Linux**

```bash
sudo apt install nmap        # Debian and Ubuntu
sudo dnf install nmap        # Fedora
```

**macOS**

```bash
brew install nmap
```

## 2. Npcap and privileges

Many Nmap features send raw packets: SYN scans, UDP scans, OS detection, and most discovery probes. What that needs depends on the platform:

* **Windows:** Npcap must be installed. If Npcap was installed in *administrators only* mode, start Genmap with **Run as administrator**.
* **Linux and macOS:** Nmap needs root for raw packets. Either start Genmap with `sudo`, or grant the Nmap binary capabilities:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
  ```

  and then pass `--privileged` through the Network tab.

Without raw packet access you can still run TCP connect scans, list scans, and most NSE scripts. **Settings, Nmap, Capabilities** shows what Genmap expects to work.

## 3. Run Genmap

### From a release build

Unzip `Genmap-<version>-windows-<arch>.zip` anywhere and run `Genmap\Genmap.exe`, or run the installer if one is provided.

### From source

```powershell
git clone https://github.com/g33l0/genmap.git
cd genmap
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -e .
genmap
```

On Linux and macOS, use `python3.13 -m venv .venv` and `source .venv/bin/activate`.

`python -m genmap` also works without installing the console script.

## 4. First start

On first start Genmap checks the Nmap installation in the background. The status bar shows the version it found. If Nmap is missing, a dialog explains what was searched and offers to open **Settings, Nmap**, where you can point Genmap at `nmap.exe` directly.

Run `genmap --diagnose` for the same checks in a terminal.

## Where Genmap stores data

| Platform | Location |
|----------|----------|
| Windows | `%LOCALAPPDATA%\Genmap\` with `config`, `data`, `logs`, and `cache` folders |
| Linux | `~/.config/genmap`, `~/.local/share/genmap`, and `~/.local/state/genmap/logs` |
| macOS | `~/Library/Application Support/Genmap` and `~/Library/Logs/Genmap` |

Set the `GENMAP_HOME` environment variable to keep everything in a single folder, for example on a USB drive.

Each scan lives in `data/scans/<run id>/` as `run.json` (configuration and status), `result.xml` (raw Nmap XML), `stdout.log`, and `stderr.log`. The file `data/genmap.sqlite3` indexes those folders and stores profiles, target groups, tags, and the list of created reports. Reports are written to `Documents\Genmap Reports` unless you choose another folder.

## Building Genmap.exe

```powershell
pip install -r requirements-dev.txt
python build_release.py
```

This runs the tests, builds `dist\Genmap\Genmap.exe` with PyInstaller, and writes a zip plus SHA256 checksum to `release\`. Options:

* `--onefile` builds a single exe. It starts slower and trips antivirus heuristics more often.
* `--installer` also builds `Genmap-<version>-setup.exe` when Inno Setup 6 is installed.
* `--skip-tests` skips the test run.

The installer does not include Nmap or Npcap. When Nmap is missing, it tells the user where to get it.
