"""Static HTML report (all values HTML-escaped; no scripts)."""

from __future__ import annotations

import html

from ..models import ToolRecord


def inventory_html(tools: dict[str, ToolRecord], stamp: str) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(t.tool_name)}</td><td>{html.escape(', '.join(t.category))}</td><td>{html.escape(t.kali_compatibility)}</td>"
        f"<td>{html.escape(t.preferred_install_method or '-')}</td><td>{html.escape(t.maintenance_status)}</td><td>{html.escape(t.security_risk)}</td></tr>"
        for t in sorted(tools.values(), key=lambda x: x.tool_name)
    )
    return ("<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>BlackArch2Kali inventory</title><style>body{{font-family:sans-serif}}td,th{{border:1px solid #ccc;padding:2px 6px}}</style></head><body>"
            f"<h1>BlackArch2Kali inventory</h1><p>Generated {html.escape(stamp)}; {len(tools)} tools</p><table><tr><th>Tool</th><th>Categories</th><th>Kali</th><th>Method</th><th>Maintenance</th><th>Risk</th></tr>{rows}</table></body></html>\n")
