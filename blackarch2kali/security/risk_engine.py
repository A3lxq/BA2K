"""Explainable risk scoring, separated into four dimensions. Evidence-based, never keyword-verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import RISK_ORDER, Compatibility, Maintenance, Method, Risk, RiskDimension, RiskFinding


def _max(levels: list[Risk]) -> Risk:
    known = [lv for lv in levels if lv is not Risk.UNKNOWN]
    return max(known, key=lambda x: RISK_ORDER[x]) if known else Risk.UNKNOWN


@dataclass
class RiskAssessment:
    findings: list[RiskFinding] = field(default_factory=list)

    def _levels(self, dim: RiskDimension | None = None, *, method: Method | None = None) -> list[Risk]:
        out = []
        for f in self.findings:
            if dim is not None and f.dimension is not dim:
                continue
            if method is Method.APT and f.scope == "upstream":
                continue
            out.append(f.level)
        return out

    def dimension(self, dim: RiskDimension) -> Risk:
        lv = self._levels(dim)
        return _max(lv) if lv else Risk.LOW

    @property
    def overall(self) -> Risk:
        return self.level_for(None)

    def level_for(self, method: Method | None) -> Risk:
        """Overall level for a given install method. Upstream-scoped findings don't apply to distro packages."""
        lv = self._levels(method=method)
        highs = [x for x in self.findings if x.level in {Risk.HIGH, Risk.CRITICAL} and x.dimension is RiskDimension.INSTALLATION and not (method is Method.APT and x.scope == "upstream")]
        if len(highs) >= 2:
            return Risk.CRITICAL  # corroborating independent installation red flags
        return _max(lv) if lv else Risk.LOW

    def blocked(self, method: Method | None, blocked_levels: list[str]) -> bool:
        return self.level_for(method).value in blocked_levels

    def by_dimension(self) -> dict[str, str]:
        return {d.value: self.dimension(d).value for d in RiskDimension}


def assess(findings: list[RiskFinding], *, maintenance: Maintenance, compat: Compatibility, repo_known: bool, missing_deps: int = 0, python2_deps: list[str] | None = None, unverified_native: bool = False) -> RiskAssessment:
    fs = list(findings)
    if maintenance is Maintenance.STALE:
        fs.append(RiskFinding(dimension=RiskDimension.MAINTENANCE, level=Risk.MEDIUM, rule="stale-upstream", message="No recent upstream activity detected; verify the project is still maintained", scope="upstream"))
    elif maintenance is Maintenance.LOW_ACTIVITY:
        fs.append(RiskFinding(dimension=RiskDimension.MAINTENANCE, level=Risk.LOW, rule="low-activity", message="Low upstream activity", scope="upstream"))
    elif maintenance is Maintenance.UNKNOWN and not repo_known:
        fs.append(RiskFinding(dimension=RiskDimension.MAINTENANCE, level=Risk.UNKNOWN, rule="maintenance-unknown", message="Maintenance state could not be determined", scope="upstream"))
    if python2_deps:
        fs.append(RiskFinding(dimension=RiskDimension.DEPENDENCY, level=Risk.MEDIUM, rule="python2-dependency", message="Depends on end-of-life Python 2 packages", evidence=", ".join(python2_deps[:5])))
    if missing_deps:
        fs.append(RiskFinding(dimension=RiskDimension.DEPENDENCY, level=Risk.MEDIUM if missing_deps > 3 else Risk.LOW, rule="unresolved-dependencies", message=f"{missing_deps} dependencies have no verified Debian/Kali equivalent"))
    if compat in {Compatibility.INCOMPATIBLE, Compatibility.LEGACY, Compatibility.SOURCE_PATCH_REQUIRED}:
        fs.append(RiskFinding(dimension=RiskDimension.COMPATIBILITY, level=Risk.MEDIUM, rule=f"compat-{compat.value.lower()}", message=f"Compatibility state is {compat.value}"))
    if unverified_native:
        fs.append(RiskFinding(dimension=RiskDimension.INSTALLATION, level=Risk.MEDIUM, rule="native-identity-unverified", message="Distro package matched by name only; upstream identity not corroborated"))
    return RiskAssessment(fs)
