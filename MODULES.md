# Modules

Genmap is organised so that Nmap is one module among several. The core talks to modules through a small contract in `genmap/modules/base.py`. It never imports tool specific code except to register a module.

## The contract

```python
class Module(abc.ABC):
    manifest: ModuleManifest                      # static description
    def initialize(self, context: ModuleContext)  # once, at startup
    def check_environment(self) -> list[Diagnostic]
    def default_configuration(self) -> BaseModel
    def validate(self, configuration) -> list[ValidationIssue]
    def shutdown(self)

class ProcessModule(Module):                      # modules that run an external program
    tool_name: str                                # used in messages, for example "Nmap"
    def build_plan(self, configuration, *, run_directory: Path) -> CommandPlan
    def create_monitor(self) -> RunMonitor        # reads console output while it runs
    def finalize_run(self, record: RunRecord, store: RunStore)
    def describe_targets(self, configuration) -> str
    def failure_line(self, lines: list[str]) -> str | None
```

`ModuleContext` gives a module the application paths, a logger, and `settings`, which always returns the current settings. Read it when you need a value instead of keeping a copy: saving the Settings page replaces the settings object.

### Running a process module

`ScanEngine.start(configuration, module_id=...)` does the same for every process module:

1. Refuses the run if the module is unknown, turned off, not a `ProcessModule`, or failed to load.
2. Calls `validate` and stops on any error.
3. Creates the run folder and record, with `describe_targets` as its summary.
4. Calls `build_plan` with that folder. The plan is a `CommandPlan`: the program, the user's arguments, arguments the module adds for itself with a reason for each, and targets. The engine starts it with `QProcess` from the argument list; there is no shell.
5. Feeds every console line to the module's monitor. `feed(line)` returns `"progress"` when `state.progress` changed and any other string for other updates. `state.problems` holds recognised failures (each with `message`, `remedy`, and `source_line`) and `state.warnings` other notes.
6. When the process ends, settles the status: cancelled, timed out, crashed, failed (non zero exit, explained by the first problem or by `failure_line`), completed with warnings (zero exit but problems were recognised), or completed.
7. Calls `finalize_run`, which reads what the tool left in the run folder, fills `record.summary`, and may downgrade a completed run to completed with warnings. If it raises, the run is still closed and marked with a warning.

`tests/test_process_module.py` runs a small Python script through this path end to end and is the best starting point for a new module.

### Manifest

```python
ModuleManifest(
    id="dns",                       # lowercase, stable, unique
    name="DNS Enumeration",
    version="0.3.0",                # the module's own version
    api_version="1.0",              # module contract version it targets
    description="...",
    capabilities=["dns-records", "subdomain-discovery"],
    platforms=["windows", "linux", "darwin"],
    external_tools=[ExternalToolRequirement(name="dig", optional=True, purpose="Fallback resolver")],
    configuration_schema=DnsConfig.model_json_schema(),
    result_schema=DnsResult.model_json_schema(),
)
```

* **Compatibility.** The registry compares the major part of `api_version` with `genmap.MODULE_API_VERSION`. A mismatch marks the module *incompatible* instead of loading it. The minor version may grow with additions that do not break existing modules.
* **Platforms.** A module that does not list the current platform is marked *unavailable*.
* **External tools.** These are declared so the UI can explain requirements. Checking them is the module's job in `check_environment`.

### Lifecycle and states

```
registered ──initialize──> ready ──check_environment──> ready | degraded | unavailable
     │                        │
     └─ incompatible          └─ error (initialize raised)
disabled (turned off by the user, any time)
```

`check_environment` returns `Diagnostic` records. The worst level decides the state: an error makes the module *unavailable*, and a warning makes it *degraded*. The latest records are kept on the module and shown on the Modules page, where **Check again** runs the check on a worker thread. A module that was unavailable is checked again each time, because the tool may have been installed since. Exceptions from modules are caught, logged, and turned into an *error* state, so one broken module cannot take the application down.

Turning a module off on the Modules page is saved in settings (`modules.disabled`) and applies at the next start too. A module that is off is still initialised, so turning it back on needs no restart; it just cannot start runs. Turning off Nmap disables **Start scan** until it is back on. Stored results stay available either way.

## The Nmap module

`genmap/modules/nmap/module.py` adapts the Nmap specific code to the contract:

* `check_environment` runs the full Nmap probe: version, capabilities, data files, capture driver, interfaces, and scripts.
* `default_configuration` returns a `ScanConfiguration`, and `validate` runs its cross field validation.
* `build_plan` builds the command with `-oX` into the run folder, `--stats-every` when progress reporting is on, and `--datadir` when a data directory is set under Settings, Nmap.
* `create_monitor` returns the `OutputMonitor` that reads Nmap's progress, port, and error lines.
* `failure_line` skips Lua tracebacks, `QUITTING!`, and the pointer to `nmap -h`.
* `finalize_run` parses the XML, fills the summary, and flags missing, truncated, or failed XML.
* `NmapModule(executable=path)` pins a specific binary without probing, for tests and embedding.
* Its manifest publishes the `ScanConfiguration` JSON schema.

## Adding a module

1. Create a package, for example `genmap/modules/dns/`, or ship it as a separate distribution.
2. Implement `Module` with a pydantic configuration model, or `ProcessModule` if it runs an external program.
3. Register it in `AppContext` for now. Phase 4 adds discovery from installed packages through the `genmap.modules` entry point group, and from a modules folder with a `module.json` manifest for tools that are not written in Python.
4. Add tests using the patterns in `tests/test_modules.py` and `tests/test_process_module.py`.

### Tools that are not Python

The contract does not assume the work happens in Python. A module can:

* launch an external executable with an argument list by returning a `CommandPlan` from `build_plan`,
* read its structured output (JSON, XML, or CSV),
* map that output into Genmap's normalised results.

Put the executable's path in the module's configuration model and validate it in `check_environment`, as the Nmap module does.

## Integrating another repository

When a separate project becomes a Genmap module:

1. Keep the tool in its own repository with its own releases.
2. Add a thin adapter module in Genmap with a manifest, a configuration model, and a mapping from the tool's output to Genmap results.
3. Declare the tool in `external_tools` with a minimum version.
4. Give the adapter fixture based tests that use the tool's real output, as the Nmap tests do.

## Domain Atlas boundary

Domain Atlas is not part of Genmap yet. The intended flow is:

```
Domain Atlas module ──> discovered domains, hostnames, addresses
                         │
                         ▼
          Genmap normalised result layer (Host, Hostname, Address)
                         │
                         ▼
          New Scan targets / Nmap module ──> services, versions, OS
                         │
                         ▼
          Correlation (phase 4) ──> investigation graph
```

The pieces that make this possible already exist. `Host`, `Address`, and `Hostname` in `genmap/core/results.py` are tool neutral. `ScanConfiguration.targets` accepts hostnames and networks from any source. Run records carry a `module_id`, so a Domain Atlas run and an Nmap run live side by side in history. Correlation needs only those shared types, not either tool's internals.
