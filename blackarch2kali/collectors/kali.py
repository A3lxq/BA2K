"""Kali Linux package index collector (kali-rolling `Packages.gz`)."""

from __future__ import annotations

from .debian import DebianCollector


class KaliCollector(DebianCollector):
    distribution = "kali"
