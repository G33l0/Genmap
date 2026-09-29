# Troubleshooting

Start with **Help, Check Nmap Installation** (F5) or `genmap --diagnose`. Most problems show up there with a suggested fix.

## "Nmap executable was not found"

Genmap searched PATH, the Windows registry, and `C:\Program Files (x86)\Nmap` and `C:\Program Files\Nmap`.

* Install Nmap from https://nmap.org/download.html, or
* open **Settings, Nmap**, choose **Browse...**, select `nmap.exe`, and choose **Save and check again**.

If you set a path and it is wrong, Genmap does not fall back to automatic search, so it never scans with a different binary than the one you chose. Clear the field to search automatically again.

## "The executable does not look like Nmap"

The configured file ran but did not print an Nmap version banner. Select the real `nmap.exe`, not the Zenmap shortcut or the installer.

## "Npcap does not appear to be installed"

Raw packet scans (SYN, UDP, OS detection, most ping types) need Npcap on Windows. Install it from https://npcap.com or rerun the Nmap installer with Npcap selected. TCP connect scans still work without it.

If Npcap *is* installed:

* It may have been installed in *administrators only* mode. Run Genmap as administrator, or reinstall Npcap without that option.
* The `npcap` service may be disabled. Check it in `services.msc`.

## "This scan type needs elevated privileges"

Nmap refused a raw packet scan. Choose one of these:

* Run Genmap as administrator on Windows, or with `sudo` on Linux and macOS.
* On Linux, grant capabilities to Nmap (see INSTALLATION.md) and select *Assume privileged* on the Network and output tab.
* Switch the TCP technique to **Connect (-sT)** and turn off OS detection.

## "Nmap could not open a network interface"

Usually Npcap is missing, or the interface picked on the Network and output tab does not exist. Leave the interface on automatic, or pick one listed under **Settings, Network**.

## "nmap-os-db missing" or another data file missing

**Settings, Nmap, Data files** lists every file Nmap needs, where Nmap will read it from, and what it contains. A missing file only affects the features listed next to it: without `nmap-os-db`, OS detection cannot run; without `nmap-service-probes`, version detection cannot run. Reinstall Nmap, or set **Data directory** to a folder with the complete set. Nmap searches `--datadir` first, then `NMAPDIR`, then your user Nmap folder, then its own folder, so a stray copy in an earlier folder wins. The table shows which copy is used. `nmap-payloads` is only listed for Nmap versions before 7.94, which moved UDP payloads into `nmap-service-probes`.

## "A custom services file makes Nmap scan the ports that file lists"

Nmap switches to fast mode whenever `--servicedb` is given and then scans the ports in that file. It refuses an explicit port list, top ports, or all ports at the same time, so Genmap stops before starting. Set the port selection back to Nmap's default, or clear the services file on the Advanced tab.

## Start scan is disabled and says the Nmap module is turned off

The Nmap module was turned off on the Modules page. Select it there and choose **Turn on**. The choice is remembered between sessions.

## The topology map shows only dotted lines

Dotted lines mean the scans did not record a route. Enable **Trace the network path (--traceroute)** on the Discovery tab and scan again; the list on the Topology page marks scans that recorded routes. Loopback targets never have a route.

## A comparison shows fewer changes than expected

Genmap only compares what both scans covered. Open **Show items that could not be compared** to see hosts outside the other scan's targets, ports only one scan probed, and services only one scan identified by version detection. The notes above the list explain differences in targets, ports, techniques, or Nmap versions.

## Progress bar never moves

Genmap shows a percentage only when Nmap prints one. Nmap prints timing estimates during long phases, and on Linux and macOS it does not print its periodic `--stats-every` lines unless it has a terminal. When no estimate exists, the bar stays in its moving *busy* state on purpose. The host, port, and service counters still update. Verbosity 1 or higher is needed for ports to appear live.

## Scan finished but results are partial

If a scan was cancelled, timed out, or Genmap closed mid scan, the results page shows a banner and lists only the hosts Nmap had finished. Scans interrupted by a crash are marked *Interrupted* in the history at the next start.

## "Unable to parse Nmap XML output"

The file is damaged or is not Nmap output. The technical details section shows the parser message. For imported files, check that they came from `nmap -oX`.

## Script errors in the output

Messages like `NSE: [shodan-api] Error: Please specify your ShodanAPI key` come from Nmap scripts that need arguments. Add them on the Scripts tab under *Script arguments*, or deselect the script. Genmap shows these messages as Nmap printed them.

## The window is blank, tiny, or badly scaled

* Genmap uses Qt's per monitor DPI scaling. If text is too small or too large, change **Settings, Appearance, Base font size**.
* Delete `window.ini` in the Genmap config folder to reset the window position.

## Antivirus flags Genmap.exe

Executables built with PyInstaller are sometimes flagged by heuristic antivirus engines even though they contain nothing harmful. Genmap's release build reduces this: it uses the one folder layout rather than a self extracting single file, does not compress with UPX, and embeds Windows version information. If a scanner still flags it, check the zip against the published `.sha256` file and report the false positive to the antivirus vendor. Nmap itself is also often flagged as a "hacking tool" by security products; that classification is about Nmap, not Genmap.

## Checking a build

`Genmap.exe --self-test report.json` exercises the bundled resources, the XML parser, command building, every page, and every theme in a throwaway data folder, then writes a JSON report. The exit code is 0 only when every check passed. It never touches your settings or scan history.

## Logs

**Settings, Logging, Open log folder** opens the application logs. Each scan's own Nmap output is in its run folder, which you can reach from **Scan History, Show files**. Set the log level to *Debug* and reproduce the problem before reporting it.

## History is empty or out of date

The scan index is rebuilt from the scan folders. Open **Settings, Storage** and choose **Rebuild scan index**. **Check database** runs SQLite's integrity check.

## "Database rebuilt" at startup

Genmap found its database file damaged, kept it as `genmap.damaged-<time>.sqlite3`, created a new one, and rebuilt scan history from the scan folders. Profiles and target groups lived only in the damaged file; export profiles you rely on from time to time so you have a copy.

## A scan appears as "files missing"

Its folder was removed from disk outside Genmap. The indexed summary stays so the history is not silently rewritten; delete the entry from **Scan History** if you no longer need it.

## Resetting Genmap

Close Genmap and delete the data folder listed under **Settings, Storage** (on Windows, `%LOCALAPPDATA%\Genmap`). This removes all settings and scan history.
