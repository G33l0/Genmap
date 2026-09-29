# Architecture

Genmap is a desktop orchestrator around external tools. Nmap is the first and most important tool, but the core is written so that Nmap is one module among several.

## Layers

```
genmap/
  ui/          PyQt6 windows, pages, widgets, item models, theme
  engine/      Process execution (QProcess) and on disk run storage
  modules/     Module contract, registry, and the Nmap module
  nmap/        Nmap adapter: discovery, probing, command building, parsing
  core/        Pure domain logic: configuration, targets, ports, results, NSE selection
  settings/    Settings schema and persistence
```

Dependencies only point downwards. `core` imports nothing from Qt, the filesystem layout, or Nmap. `nmap` depends on `core` and uses `subprocess` only for short diagnostic queries. `engine` owns long running processes and is the only place that uses `QProcess`. `ui` talks to everything through `AppContext`, which holds the settings store, module registry, scan engine, run store, and theme.

## Scan lifecycle

```
New Scan form ──dump──> dict ──validate──> ScanConfiguration
                                                │
                    validate_configuration()  ◀─┤  cross field checks
                    assess_intrusiveness()    ◀─┤  confirmation notices
                                                ▼
                               build_command_plan() ──> CommandPlan
                                                │  user args + managed args + targets
                                                ▼
                                ScanEngine.start() ──> ScanJob (QProcess)
                                                │  stdout/stderr ──> OutputMonitor
                                                │  run.json, stdout.log, result.xml
                                                ▼
                                parse_nmap_xml_file() ──> ScanResult
                                                ▼
                                   Results page models
```

1. **Configuration.** The New Scan page's tabs each write their part into a plain dict. Pydantic validates the whole dict in one go, so a typo in any field becomes a readable issue instead of an exception while typing. `validate_configuration` then checks combinations that are individually valid but contradict each other.
2. **Command plan.** `build_command_plan` translates the model into arguments. It keeps three groups apart: arguments from the configuration, arguments Genmap adds for itself (`-oX` for the result file and `--stats-every` for progress), and targets. The Command Inspector shows these groups, so it is always clear which options the user chose.
3. **Execution.** `ScanJob` wraps a `QProcess` started with an argument list. Output is decoded incrementally, split into lines, written to line buffered log files, and fed to `OutputMonitor`, which extracts only what Nmap actually printed: timing estimates, discovered ports, host reports, and known error messages. Cancellation terminates the process, and on Windows kills it, because console programs ignore close requests. A watchdog kills it if terminate is ignored.
4. **Storage.** `RunStore` gives each run a folder. The folder is the durable record, and raw output is never discarded. Runs left in a running state by a crash are marked *interrupted* at the next start, and their partial XML is summarised.
5. **Parsing.** The XML parser uses `defusedxml`. Unknown elements and attributes are kept in `extra` fields instead of being dropped. If a file ends early, the parser cuts it after the last complete `<host>`, closes the document, and flags the result as truncated.

## Accuracy rules

Genmap tries hard not to claim more than Nmap established:

* **Script warnings are resolved, not guessed.** `core/nse.py` evaluates `--script` expressions against the installed catalog with Nmap's precedence (`not` above `and` above `or`), so warnings name real scripts.
* **Errors are matched on Nmap's exact wording.** `OutputMonitor` only raises a problem for lines Nmap prints when something fails, never for script output that happens to contain the same words.
* **Probed and guessed services are kept apart.** `Service.is_probed` separates version detection results from names Nmap reads from its port table.
* **A zero exit code is not automatically a success.** If Nmap reported a recognised problem, the run ends as *Completed with warnings*.

## Why these choices

**Typed configuration instead of command strings.** A model can be validated, diffed, serialised into history, turned into profiles, and rendered into a UI. It also makes command injection structurally impossible: the model holds values, the builder chooses where they go, and nothing is ever joined into a shell line.

**Advanced arguments stay first class.** Nmap evolves faster than any GUI. The advanced field is tokenised with Windows friendly rules, so backslashes survive and quotes group values. Only options Genmap must own are refused, such as output files and `-iL`. Everything else is appended to the command and shown in the preview.

**Capabilities are advice, not gates.** Genmap predicts what should work from the Nmap version, build libraries, capture driver, and privileges. When it is not sure, it says *unknown* and lets Nmap decide. It never blocks a scan because of its own guess.

**No invented progress.** Nmap prints progress only when it has an estimate. Without one, the progress bar is indeterminate. On Linux and macOS, Nmap stops printing `--stats-every` lines when it has no terminal, so progress there usually stays indeterminate. Counters come only from lines Nmap printed.

**Files first, database next.** Phase 1 stores runs as folders with JSON and XML. Phase 2 adds SQLite through SQLAlchemy and Alembic as an index and query layer on top of those folders. The folders remain the source of truth, so a database migration can never lose raw Nmap output.

## Threads

The UI thread never blocks on Nmap:

* `QProcess` delivers scan output through signals.
* Environment probing (`nmap --version` and `--iflist`) runs on the global `QThreadPool` and reports back with a queued signal.
* Result XML is parsed on the thread pool through `ui/tasks.run_in_background`. A load token discards stale results when the user switches scans quickly.
* Console output is batched and flushed every 80 ms, so verbose or debug scans do not flood the event loop.

## Module boundary

See [MODULES.md](MODULES.md). In short, the core only knows `Module`, `ModuleManifest`, `ModuleRegistry`, and the shared `Diagnostic` and `ValidationIssue` types. The Nmap module adapts the Nmap specific code to that contract. A future Domain Atlas module, or any other tool, can feed normalised hosts into the same result layer without the core learning about it.

## UI structure

`MainWindow` holds the sidebar and a `QStackedWidget` of pages. Each page subclasses `BasePage` and gets `on_shown` and `on_hidden` hooks. Results use `QStandardItemModel` subclasses with a custom `QSortFilterProxyModel`. Every row stores the searchable text for each filter field in a custom role, so filtering by OS, CPE, or NSE output works even though those fields are not shown as columns. The theme is a pair of palettes rendered into a single style sheet. The dashboard uses `ResponsiveGrid`, which reflows cards from two columns to one as the window narrows.
