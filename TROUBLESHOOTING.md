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

## Resetting Genmap

Close Genmap and delete the data folder listed under **Settings, Storage** (on Windows, `%LOCALAPPDATA%\Genmap`). This removes all settings and scan history.
