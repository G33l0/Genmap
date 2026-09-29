# Development

## Setup

```bash
python3.13 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
pip install -r requirements-dev.txt
```

## Running

```bash
genmap                             # or: python -m genmap
GENMAP_HOME=/tmp/genmap-dev genmap # isolated data folder
GENMAP_DEBUG=1 genmap --log-level DEBUG
```

## Tests

```bash
pytest                             # everything
pytest -m "not integration"        # skip tests that run the real Nmap
pytest tests/test_command_builder.py -q
```

The suite has three kinds of tests:

* **Unit tests** cover targets, ports, time values, the configuration model, the command builder, argument review, the XML parser, the output monitor (including banners and script output that must not be mistaken for errors), NSE expression resolution, scan outcomes, version and interface parsing, capabilities, settings, the run store, modules, presets, and intrusiveness notices. They need no network and no Nmap.
* **UI tests** (`tests/test_ui.py`) build the real main window with pytest-qt on Qt's offscreen platform and exercise the New Scan form, result filtering, history, and settings.
* **Integration tests** (`tests/test_integration_nmap.py`) run the installed Nmap against `127.0.0.1` using list and connect scans, so no privileges or network access are needed. They are skipped automatically when Nmap is not installed.

Fixtures in `tests/fixtures` include real Nmap 7.94 output (a localhost scan with version and OS detection, a ping sweep, a list scan, the matching console output, and `--version` and `--iflist` output) plus a hand written multi host LAN inventory modelled on Nmap 7.95 output. There are also deliberately broken files: a truncated scan, an entity expansion attack, and XML that is not from Nmap.

On a headless Linux machine Qt needs `libegl1`, `libxkbcommon0`, `libfontconfig1`, and `libdbus-1-3`. The tests set `QT_QPA_PLATFORM=offscreen` themselves.

## Self test

`python -m genmap --self-test report.json` runs the same headless checks CI runs against the packaged Windows executable. CI starts `Genmap.exe` with `Start-Process -Wait` because PowerShell does not wait for windowed programs, and it fails the job unless the report says `ok` and `frozen`.

## Database changes

Change the models in `genmap/storage/models.py`, then generate and review a migration:

```bash
alembic revision --autogenerate -m "describe the change"
```

Replace custom column types in the generated file with plain SQLAlchemy types so old migrations never depend on current model code. `tests/test_storage.py::test_migrations_match_models` fails if the migrations and the models drift apart.

## Conventions

* Keep `genmap/core` free of Qt and I/O. If something needs a process or a widget, it belongs in another layer.
* Errors meant for people are `GenmapError` subclasses with a plain `message`, an optional `remedy`, and technical `details`. The UI shows the first two and puts the details behind a button.
* Never build shell strings. Pass argument lists to `QProcess` or `subprocess`.
* Nothing in the UI should claim more than Nmap reported. If a value is unknown, say so.
* Comments explain *why*, not *what*.

## Changing the logo

Edit `genmap/resources/branding/genmap-logo.svg`, then regenerate the PNG and ICO files:

```bash
python scripts/generate_icons.py
```

## Releasing

1. Update `__version__` in `genmap/__init__.py` and `version` in `pyproject.toml`.
2. On Windows, run `python build_release.py --installer`.
3. Test `dist\Genmap\Genmap.exe` on a machine with and without Nmap installed.
4. Publish the zip, its `.sha256` file, and the installer.
