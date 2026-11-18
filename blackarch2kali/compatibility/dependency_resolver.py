"""Graph-based dependency resolution for BlackArch -> Debian/Kali.

Arch dependency names are never assumed to equal Debian names: each is resolved against the real
BlackArch inventory and Debian/Kali indexes (exact names, validated aliases). Resolution never
modifies system repositories; it only produces plans and findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..collectors.debian import DebIndex
from ..models import BlackArchPackage, DebMatch


def parse_relation(raw: str) -> tuple[str, str | None, str | None]:
    """'foo>=1.2' / 'foo: reason' -> (name, op, version)."""
    raw = raw.strip()
    name_part = re.split(r"(<=|>=|<|>|=|:)", raw, maxsplit=1)
    name = name_part[0].strip()
    m = re.match(r"^[A-Za-z0-9][A-Za-z0-9+._@-]*$", name)
    if not m:
        raise ValueError(f"invalid dependency: {raw!r}")
    op_m = re.search(r"(<=|>=|<|>|=)\s*([^\s:]+)", raw[len(name):])
    return name, (op_m.group(1) if op_m else None), (op_m.group(2) if op_m else None)


def _order(ch: str) -> int:
    if ch == "~":
        return -1
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256


def _cmp_part(a: str, b: str) -> int:
    """Debian version-part comparison (dpkg algorithm)."""
    while a or b:
        da = re.match(r"^\D*", a)
        db = re.match(r"^\D*", b)
        ta, tb = (da.group(0) if da else ""), (db.group(0) if db else "")
        a, b = a[len(ta):], b[len(tb):]
        for i in range(max(len(ta), len(tb))):
            oa = _order(ta[i]) if i < len(ta) else 0
            ob = _order(tb[i]) if i < len(tb) else 0
            if oa != ob:
                return -1 if oa < ob else 1
        na_m, nb_m = re.match(r"^\d*", a), re.match(r"^\d*", b)
        na, nb = (na_m.group(0) if na_m else ""), (nb_m.group(0) if nb_m else "")
        a, b = a[len(na):], b[len(nb):]
        ia, ib = int(na or 0), int(nb or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def compare_versions(a: str, b: str) -> int:
    """Compare upstream versions. Epoch and Debian/Arch revision are stripped (documented approximation)."""
    def upstream(v: str) -> str:
        v = v.split(":", 1)[1] if ":" in v else v
        return v.rsplit("-", 1)[0] if "-" in v else v

    return _cmp_part(upstream(a), upstream(b))


def satisfies(version: str, op: str | None, wanted: str | None) -> bool:
    if not op or not wanted:
        return True
    c = compare_versions(version, wanted)
    return {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]


@dataclass
class Resolution:
    root: str
    blackarch_deps: list[str] = field(default_factory=list)  # deps that are themselves BlackArch packages
    apt_packages: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    version_conflicts: list[dict[str, str]] = field(default_factory=list)
    arch_conflicts: list[str] = field(default_factory=list)
    package_conflicts: list[str] = field(default_factory=list)
    alternatives: dict[str, list[str]] = field(default_factory=dict)
    cycles: list[list[str]] = field(default_factory=list)
    install_order: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Tarjan SCC; returns components with >1 node or a self-loop."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on: set[str] = set()
    out: list[list[str]] = []
    counter = [0]

    def strong(v: str) -> None:
        # iterative Tarjan to avoid recursion limits on large graphs
        work = [(v, iter(graph.get(v, [])))]
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in graph:
                    continue
                if w not in index:
                    index[w] = low[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on.add(w)
                    work.append((w, iter(graph.get(w, []))))
                    advanced = True
                    break
                if w in on:
                    low[node] = min(low[node], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) > 1 or node in graph.get(node, []):
                    out.append(sorted(comp))

    for v in sorted(graph):
        if v not in index:
            strong(v)
    return out


class DependencyResolver:
    def __init__(self, packages: dict[str, BlackArchPackage], kali: DebIndex | None, debian: DebIndex | None,
                 host_arch: str = "amd64", aliases: dict[str, list[str]] | None = None) -> None:
        self.packages = packages
        self.indexes = [i for i in (kali, debian) if i is not None]
        self.host_arch = host_arch
        self.aliases = aliases or {}
        self.provides: dict[str, str] = {}
        for pkg in packages.values():
            for p in pkg.provides:
                try:
                    self.provides.setdefault(parse_relation(p)[0], pkg.name)
                except ValueError:
                    continue
        self._graph: dict[str, list[str]] | None = None

    def _lookup_deb(self, name: str) -> tuple[DebMatch | None, list[str]]:
        cands = [name, *self.aliases.get(name, [])]
        if name.startswith("python-"):
            cands.append(f"python3-{name[7:]}")
        found: list[DebMatch] = []
        for idx in self.indexes:
            for c in cands:
                m = idx.get(c)
                if m:
                    found.append(m)
                    break
            else:
                for c in cands:
                    real = idx.provides.get(c)
                    if real:
                        m = idx.get(real[0])
                        if m:
                            found.append(m)
                            break
        alt = sorted({m.package for m in found})
        return (found[0] if found else None), alt

    def resolve_graph(self) -> dict[str, list[str]]:
        """BlackArch-internal dependency graph (edges to other BlackArch packages); computed once."""
        if self._graph is not None:
            return self._graph
        graph: dict[str, list[str]] = {}
        for name, pkg in self.packages.items():
            edges = []
            for raw in pkg.depends:
                try:
                    dep = parse_relation(raw)[0]
                except ValueError:
                    continue
                target = dep if dep in self.packages else self.provides.get(dep)
                if target:
                    edges.append(target)
            graph[name] = sorted(set(edges))
        self._graph = graph
        return graph

    def resolve(self, name: str) -> Resolution:
        res = Resolution(root=name)
        graph = self.resolve_graph()
        seen: set[str] = set()
        order: list[str] = []

        def visit(start: str) -> None:
            """Iterative post-order DFS (dependencies before dependents); cycle-safe via `seen`."""
            stack = [(start, iter(graph.get(start, [])))]
            seen.add(start)
            while stack:
                node, it = stack[-1]
                for d in it:
                    if d not in seen:
                        seen.add(d)
                        stack.append((d, iter(graph.get(d, []))))
                        break
                else:
                    stack.pop()
                    order.append(node)

        pkg = self.packages.get(name)
        if pkg is None:
            res.missing.append(name)
            return res
        visit(name)
        res.install_order = order
        res.cycles = [c for c in find_cycles({n: graph.get(n, []) for n in seen}) if name in c or set(c) & seen]
        apt: set[str] = set()
        chosen: dict[str, DebMatch] = {}
        for n in order:
            p = self.packages[n]
            if n != name:
                res.blackarch_deps.append(n)
            for raw in p.depends:
                try:
                    dep, op, ver = parse_relation(raw)
                except ValueError:
                    res.missing.append(f"{n}: unparsable dependency {raw!r}")
                    continue
                if dep in self.packages or dep in self.provides:
                    continue
                match, alts = self._lookup_deb(dep)
                if match is None:
                    res.missing.append(dep)
                    continue
                if len(alts) > 1:
                    res.alternatives[dep] = alts
                if match.architecture not in {"all", self.host_arch}:
                    res.arch_conflicts.append(f"{dep} -> {match.package} ({match.architecture})")
                if not satisfies(match.version, op, ver):
                    res.version_conflicts.append({"dependency": dep, "required": f"{op}{ver}", "available": match.version, "package": match.package})
                apt.add(match.package)
                chosen[match.package] = match
        for m in chosen.values():
            for c in m.conflicts:
                cname = parse_relation(c.split("(")[0].strip())[0] if c.strip() else ""
                if cname in chosen:
                    res.package_conflicts.append(f"{m.package} conflicts with {cname}")
        res.apt_packages = sorted(apt)
        res.missing = sorted(set(res.missing))
        return res
