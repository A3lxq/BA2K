"""Compatibility engine: combines package mapping, upstream evidence and policy into states + ranked options."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Compatibility, InstallOption, Maintenance, Method
from .install_strategy import StrategyContext, build_options, rank_options
from .package_mapper import PackageMapping

_METHOD_STATE = {
    Method.PIPX: Compatibility.AVAILABLE_PIPX, Method.PYTHON_VENV: Compatibility.AVAILABLE_PIPX,
    Method.CARGO: Compatibility.AVAILABLE_CARGO, Method.GO: Compatibility.AVAILABLE_GO,
    Method.NPM: Compatibility.AVAILABLE_NPM, Method.GEM: Compatibility.AVAILABLE_GEM,
    Method.DOCKER: Compatibility.AVAILABLE_DOCKER, Method.SOURCE_BUILD: Compatibility.AVAILABLE_SOURCE,
}
_PRIORITY = [
    Compatibility.NATIVE_KALI, Compatibility.NATIVE_DEBIAN, Compatibility.AVAILABLE_PIPX, Compatibility.AVAILABLE_GO,
    Compatibility.AVAILABLE_CARGO, Compatibility.AVAILABLE_NPM, Compatibility.AVAILABLE_GEM, Compatibility.AVAILABLE_DOCKER,
    Compatibility.AVAILABLE_SOURCE,
]


@dataclass
class CompatResult:
    states: list[Compatibility] = field(default_factory=list)
    primary: Compatibility = Compatibility.UNKNOWN
    options: list[InstallOption] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def evaluate(ctx: StrategyContext, mapping: PackageMapping) -> CompatResult:
    ctx.kali, ctx.debian = mapping.kali, mapping.debian
    res = CompatResult(notes=list(mapping.notes))
    states: set[Compatibility] = set()
    for m, st in ((mapping.kali, Compatibility.NATIVE_KALI), (mapping.debian, Compatibility.NATIVE_DEBIAN)):
        if m is None:
            continue
        if m.architecture in {"all", ctx.host_arch}:
            states.add(st)
        else:
            res.notes.append(f"{m.distribution}:{m.package} is {m.architecture}-only; host is {ctx.host_arch}")
    options = build_options(ctx)
    res.options = rank_options(options, ctx.maintenance, ctx.policy)
    states.update(_METHOD_STATE[o.method] for o in options if o.method in _METHOD_STATE)
    legacy = ctx.maintenance in {Maintenance.ARCHIVED, Maintenance.STALE}
    py2 = ctx.python2
    if py2:
        res.notes.append("upstream appears to be Python 2 only")
    primary = next((s for s in _PRIORITY if s in states), None)
    if primary is None:
        if py2 and ctx.repo is not None:
            primary = Compatibility.SOURCE_PATCH_REQUIRED
        elif legacy:
            primary = Compatibility.LEGACY
        elif (mapping.kali or mapping.debian) and not states or ctx.pkg.arch not in {"any", "UNKNOWN", "x86_64"} and ctx.host_arch != "amd64":
            primary = Compatibility.INCOMPATIBLE
        else:
            primary = Compatibility.UNKNOWN
    if legacy and primary not in {Compatibility.LEGACY}:
        states.add(Compatibility.LEGACY)
    if py2:
        states.add(Compatibility.SOURCE_PATCH_REQUIRED)
    states.add(primary)
    res.states = sorted(states, key=lambda s: _PRIORITY.index(s) if s in _PRIORITY else 50)
    res.primary = primary
    return res
