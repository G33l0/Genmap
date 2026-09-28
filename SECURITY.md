# Security

Genmap launches a powerful network tool with user supplied input and parses files that could have been tampered with. This document describes how it handles both.

## Authorized use

Genmap is for authorized security testing, administration, research, and lab work. Only scan systems you own or have written permission to test. Genmap never starts a scan on its own: every scan begins with an explicit action, and the command is shown before it runs.

## Process execution

* Nmap is always started with an argument list through `QProcess` or `subprocess`, never with `shell=True` and never through `cmd.exe` or `/bin/sh`. Shell metacharacters in any field reach Nmap as literal text. The tests check this with values like `; rm -rf /` and `$(id)`.
* Targets are validated before use. Anything starting with `-` is refused so it cannot be read as an option. Control characters, quotes, and shell operators are refused as well.
* Port lists, time values, TCP flags, payload hex, MTU, and similar fields are validated by type.
* Advanced arguments are tokenised by Genmap, not by a shell. Options that would redirect Genmap's own output or inputs are refused: `-oX`, `-oN`, `-oA`, `-oG`, `-oS`, `--append-output`, `-iL`, `--resume`, and `--stats-every`. All other options pass through and are shown in the preview.
* The Nmap path must point at an existing file. Genmap runs `--version` on it and refuses to scan with it unless the output identifies it as Nmap.
* Scans run with Genmap's own privileges. Genmap never elevates itself.

## Intrusive configurations

Before a scan starts, Genmap lists anything that deserves a second look:

* NSE categories that can disrupt or attack services: `intrusive`, `brute`, `dos`, `exploit`, `fuzzer`, and `malware`. The list is configurable.
* Script wildcards, and script names that look like brute force or denial of service scripts.
* Decoys, spoofed addresses or MAC addresses, bad checksums, fragmentation, and idle or FTP bounce scans.
* Aggressive timing, very high packet rates, large address ranges, and random Internet targets (`-iR`).

High risk items require ticking an authorization box before the Start button is enabled. The category labels come from Nmap's classification. Genmap does not describe any script as safe beyond what Nmap says.

## Parsing

* Nmap XML is parsed with `defusedxml`. Documents that declare entities, including entity expansion and external entities, are rejected. The tests include a billion laughs file and an external entity file.
* XML that is not Nmap output is rejected with a clear message.
* Unknown elements are stored as data. They are never evaluated.
* NSE script contents are never read or executed by Genmap. Script names come from Nmap's `script.db`, which is parsed as text. Nmap alone runs scripts.
* Result details are HTML escaped before display, so hostile banners or script output cannot inject markup into the UI.

## Local data

* Settings are written atomically to a temporary file and then renamed. A corrupt settings file is kept as a timestamped backup and replaced by defaults, and the user is told.
* Run identifiers are checked before being used as folder names, so path traversal is not possible.
* Scan results, console output, and logs are stored unencrypted in the user's profile. They can contain sensitive network information. Protect the Genmap data folder the way you would protect any scan output.
* The application log records commands and statuses. It does not record NSE script arguments separately, but the command line in each run record includes them. Do not put credentials in script arguments unless you accept that they are stored with the run.

## Reporting a vulnerability

Please report security issues privately through GitHub's security advisory feature on the repository instead of opening a public issue.
