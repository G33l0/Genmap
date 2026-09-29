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
```

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
disabled (by the user, any time)
```

`check_environment` returns `Diagnostic` records. The worst level decides the state: an error makes the module *unavailable*, and a warning makes it *degraded*. Exceptions from modules are caught, logged, and turned into an *error* state, so one broken module cannot take the application down.

## The Nmap module

`genmap/modules/nmap/module.py` adapts the Nmap specific code to the contract:

* `check_environment` runs the full Nmap probe: version, capabilities, capture driver, interfaces, and scripts.
* `default_configuration` returns a `ScanConfiguration`.
* `validate` runs the configuration's cross field validation.
* Its manifest publishes the `ScanConfiguration` JSON schema.

Scan execution currently goes through `genmap.engine.ScanEngine`. Phase 3 adds a generic `execute`, `parse`, and `export` interface to the contract. The engine is built around that shape: a job with a record, a command plan, streamed output, and a parsed result.

## Adding a module

1. Create a package, for example `genmap/modules/dns/`, or ship it as a separate distribution.
2. Implement `Module` with a pydantic configuration model.
3. Register it in `AppContext` for now. Phase 4 adds discovery from installed packages through the `genmap.modules` entry point group, and from a modules folder with a `module.json` manifest for tools that are not written in Python.
4. Add unit tests using the pattern in `tests/test_modules.py`.

### Tools that are not Python

The contract does not assume the work happens in Python. A module can:

* launch an external executable with an argument list, the same way `ScanEngine` launches Nmap,
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
