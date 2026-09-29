# Security

Genmap launches a powerful network tool with user supplied input and parses files that could have been tampered with. This document describes how it handles both.

## Authorized use

Genmap is for authorized security testing, administration, research, and lab work. Only scan systems you own or have written permission to test. Genmap never starts a scan on its own: every scan begins with an explicit action, and the command is shown before it runs.

## Process execution

* Nmap is always started with an argument list through `QProcess` or `subprocess`, never with `shell=True` and never through `cmd.exe` or `/bin/sh`. Shell metacharacters in any field reach Nmap as literal text. The tests check this with values like `; rm -rf /` and `$(id)`.
* Targets are validated before use. Anything starting with `-` is refused so it cannot be read as an option. Control characters, quotes, and shell operators are refused as well.
* Port lists, time values, TCP flags, payload hex, MTU, and similar fields are validated by type.
* Advanced arguments are tokenised by Genmap, not by a shell. Options that would redirect Genmap's own output or inputs are refused: `-oX`, `-oN`, `-oA`, `-oG`, `-oS`, `--append-output`, `-iL`, `--resume`, and `--stats-every`. `--datadir`, `--servicedb`, and `--versiondb` are refused there too, because they have dedicated fields and a second copy would silently override the first. All other options pass through and are shown in the preview.
* The Nmap path must point at an existing file. Genmap runs `--version` on it and refuses to scan with it unless the output identifies it as Nmap.
* Data directory and data file paths are checked for control characters and must exist before a scan starts. The data directory from Settings is passed to Nmap as `--datadir` and shown in the Command Inspector as an argument Genmap added, so the scripts and databases Genmap displays are the ones Nmap reads.
* Every module that runs a program goes through the same engine: an argument list, no shell, the same logging, cancellation, and time limit. A module cannot bypass this, because the engine starts the process itself from the plan the module returns.
* Scans run with Genmap's own privileges. Genmap never elevates itself.

## Intrusive configurations

Before a scan starts, Genmap lists anything that deserves a second look:

* NSE categories that can disrupt or attack services: `intrusive`, `brute`, `dos`, `exploit`, `fuzzer`, and `malware`. The list is configurable.
* Script wildcards, and script names that look like brute force or denial of service scripts.
* Decoys, spoofed addresses or MAC addresses, bad checksums, fragmentation, and idle or FTP bounce scans.
* Aggressive timing, very high packet rates, large address ranges, and random Internet targets (`-iR`).

For NSE, Genmap evaluates the selection exactly as Nmap does, against the installed `script.db`: categories, names, wildcards, and `and`, `or`, `not` with parentheses. The warning lists the scripts that will actually run and belong to an intrusive category. A selection such as `default` produces no warning, `ssl-*` names only `ssl-enum-ciphers`, and `not intrusive` still reports the `brute` scripts it keeps. Files and names missing from the database are reported as unverifiable. When the database is unavailable Genmap falls back to reading the expressions and says so.

High risk items require ticking an authorization box before the Start button is enabled. The category labels come from Nmap's classification. Genmap does not describe any script as safe beyond what Nmap says.

## Parsing

* Nmap XML is parsed with `defusedxml`. Documents that declare entities, including entity expansion and external entities, are rejected. The tests include a billion laughs file and an external entity file.
* XML that is not Nmap output is rejected with a clear message.
* Unknown elements are stored as data. They are never evaluated.
* NSE script contents are never read or executed by Genmap. Script names come from Nmap's `script.db`, which is parsed as text. Nmap alone runs scripts.
* Result details are HTML escaped before display, so hostile banners or script output cannot inject markup into the UI.

## Reporting only what Nmap reported

* Failure messages are matched against Nmap's exact wording, so script output or banners that merely mention words like Npcap are not treated as errors. Every explanation quotes the Nmap line it came from.
* A scan that exits cleanly but hit a recognised problem, such as a name that did not resolve, finishes as *Completed with warnings* instead of *Completed*.
* Service names count as identified only when version detection confirmed them.

## Comparisons and maps

* Scan comparisons state what Nmap reported in each scan and keep Genmap's reading of a difference visibly separate. Hosts, ports, and services that only one scan covered are shown as context and never counted as changes, so a narrower second scan cannot make hosts look like they disappeared.
* The topology map draws only relationships Nmap recorded. Hops that did not reply stay separate unknowns and are never merged into an assumed router.
* Comparison HTML exports carry the same escaping and Content Security Policy as reports. Map exports render hostnames and addresses as text; the tests export a map whose hostname contains markup and check the SVG is still well formed.
* The diagnostic report on the Settings page leaves out interface addresses and MAC addresses, since it is meant to be pasted into bug reports.

## Reports

HTML reports are single files with no scripts and no remote resources. Every value that came from a scanned system (banners, titles, script output) is HTML escaped, and each page carries a Content Security Policy that blocks scripts, frames, and remote loads, so a report remains inert even when opened from an untrusted location. The tests include a banner containing `<script>` and an `<iframe>` in script output.

## Local data

* The SQLite database enforces foreign keys and is backed up before every schema migration. Profile and target group imports are size limited and validated through the same models the interface uses.
* Settings are written atomically to a temporary file and then renamed. A corrupt settings file is kept as a timestamped backup and replaced by defaults, and the user is told.
* Run identifiers are checked before being used as folder names, so path traversal is not possible.
* Scan results, console output, and logs are stored unencrypted in the user's profile. They can contain sensitive network information. Protect the Genmap data folder the way you would protect any scan output.
* The application log records commands and statuses. It does not record NSE script arguments separately, but the command line in each run record includes them. Do not put credentials in script arguments unless you accept that they are stored with the run.

## Reporting a vulnerability

Please report security issues privately through GitHub's security advisory feature on the repository instead of opening a public issue.
