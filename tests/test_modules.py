import logging

import pytest
from pydantic import BaseModel

from genmap.core.diagnostics import Diagnostic, DiagnosticLevel
from genmap.core.scan_config import ScanConfiguration, ValidationIssue
from genmap.errors import ModuleError
from genmap.modules import Module, ModuleContext, ModuleManifest, ModuleRegistry, ModuleState
from genmap.modules.nmap import NmapModule


class EchoConfig(BaseModel):
    message: str = "hi"


class EchoModule(Module):
    def __init__(self, manifest: ModuleManifest, diagnostics=None, fail_init=False):
        super().__init__()
        self._manifest = manifest
        self._diagnostics = diagnostics or []
        self._fail_init = fail_init
        self.shut_down = False

    @property
    def manifest(self):
        return self._manifest

    def initialize(self, context):
        if self._fail_init:
            raise RuntimeError("tool not found")
        super().initialize(context)

    def check_environment(self):
        return self._diagnostics

    def default_configuration(self):
        return EchoConfig()

    def validate(self, configuration):
        return [] if configuration.message else [ValidationIssue(severity="error", message="empty")]

    def shutdown(self):
        self.shut_down = True


def manifest(**overrides):
    data = {"id": "echo", "name": "Echo", "version": "1.0.0"}
    data.update(overrides)
    return ModuleManifest(**data)


@pytest.fixture
def context(app_paths):
    return ModuleContext(paths=app_paths, settings=None, logger=logging.getLogger("test"))


def test_manifest_validation():
    with pytest.raises(ValueError):
        ModuleManifest(id="Bad Id", name="x", version="1")
    assert manifest().is_api_compatible("1.4")
    assert not manifest(api_version="2.0").is_api_compatible("1.0")


def test_registry_lifecycle(context):
    registry = ModuleRegistry()
    ok = EchoModule(manifest())
    degraded = EchoModule(manifest(id="warn"), [Diagnostic(DiagnosticLevel.WARNING, "old version")])
    broken = EchoModule(manifest(id="broken"), fail_init=True)
    for module in (ok, degraded, broken):
        registry.register(module)
    registry.initialize_all(context)
    assert broken.state == ModuleState.ERROR and "tool not found" in broken.last_error
    report = registry.check_all()
    assert ok.state == ModuleState.READY
    assert degraded.state == ModuleState.DEGRADED
    assert "broken" not in report
    registry.shutdown_all()
    assert ok.shut_down and degraded.shut_down


def test_duplicate_and_incompatible_modules():
    registry = ModuleRegistry()
    registry.register(EchoModule(manifest()))
    with pytest.raises(ModuleError):
        registry.register(EchoModule(manifest()))
    future = EchoModule(manifest(id="future", api_version="9.0"))
    registry.register(future)
    assert future.state == ModuleState.INCOMPATIBLE


def test_platform_filter():
    registry = ModuleRegistry()
    module = EchoModule(manifest(id="nowhere", platforms=["plan9"]))
    registry.register(module)
    assert module.state == ModuleState.UNAVAILABLE


def test_enable_disable(context):
    registry = ModuleRegistry()
    module = EchoModule(manifest())
    registry.register(module)
    registry.set_enabled("echo", False)
    registry.initialize_all(context)
    assert module.state == ModuleState.DISABLED and not registry.is_enabled("echo")
    registry.set_enabled("echo", True)
    assert registry.is_enabled("echo")
    with pytest.raises(ModuleError):
        registry.set_enabled("missing", True)


def test_nmap_module_contract():
    module = NmapModule()
    assert module.manifest.id == "nmap"
    assert "port-scan" in module.manifest.capabilities
    assert module.manifest.configuration_schema["title"] == "ScanConfiguration"
    config = module.default_configuration()
    assert isinstance(config, ScanConfiguration)
    issues = module.validate(config)
    assert any(i.message == "No targets specified." for i in issues)
    assert module.executable() is None
