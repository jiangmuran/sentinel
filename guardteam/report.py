"""Render an AuditLedger into a self-contained HTML compliance report.

Turns the hash-chained decision trail into something a compliance officer or
judge actually reads: an integrity badge, per-verdict tallies, and a table of
every decision with its reasons. No dependencies, no external assets.
"""

from __future__ import annotations

import html
from typing import Any

_VERDICT = {
    "approved": ("#1a7f4b", "#e7f6ee", "通过"),
    "blocked": ("#b42318", "#fdeceb", "拦截"),
    "held": ("#b7791f", "#fdf4e3", "暂缓复核"),
}

_CSS = """
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",
  "Noto Sans SC",sans-serif;color:#1a2230;background:#f6f8fb}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px 60px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:#5b6675;font-size:13px;margin-bottom:20px}
.badge{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;
  border-radius:10px;font-weight:700;font-size:14px;margin-bottom:22px}
.ok{background:#e7f6ee;color:#1a7f4b}
.bad{background:#fdeceb;color:#b42318}
.tallies{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:22px}
.tally{flex:1;min-width:120px;background:#fff;border:1px solid #e5eaf1;
  border-radius:12px;padding:14px 16px}
.tally .n{font-size:26px;font-weight:800}
.tally .l{font-size:12px;color:#5b6675}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5eaf1;
  border-radius:12px;overflow:hidden;font-size:13.5px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #eef2f7;vertical-align:top}
th{background:#f0f4f9;font-size:12px;color:#5b6675;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-weight:700;font-size:12px}
.amt{font-variant-numeric:tabular-nums;white-space:nowrap}
.reasons{color:#5b6675;font-size:12.5px;margin:0;padding-left:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#8792a2}
footer{margin-top:20px;color:#8792a2;font-size:12px}
"""


def render_html(ledger, title: str = "GuardTeam 合规审计报告") -> str:
    v = ledger.verify()
    entries = ledger.entries
    counts: dict[str, int] = {"approved": 0, "blocked": 0, "held": 0}
    for e in entries:
        d = e["record"].get("decision")
        if d in counts:
            counts[d] += 1

    if v["ok"]:
        badge = ('<div class="badge ok">✔ 账本完整性校验通过 · '
                 f'{v["entries"]} 条记录 · 哈希链未被篡改</div>')
    else:
        badge = ('<div class="badge bad">✘ 完整性校验失败 · '
                 f'第 {v["broken_at"]} 条记录异常:{html.escape(v["reason"])}</div>')

    tallies = "".join(
        f'<div class="tally"><div class="n">{counts[k]}</div>'
        f'<div class="l">{_VERDICT[k][2]}</div></div>'
        for k in ("approved", "held", "blocked"))

    rows = []
    for e in entries:
        r = e["record"]
        dec = r.get("decision", "?")
        fg, bg, label = _VERDICT.get(dec, ("#5b6675", "#eef2f7", dec))
        reasons = "".join(f"<li>{html.escape(str(x))}</li>"
                          for x in r.get("reasons", [])) or "<li>—</li>"
        sig = (r.get("receipt_signature") or "")[:16]
        rows.append(
            f"<tr><td>{e['seq']}</td>"
            f"<td>{html.escape(str(r.get('case_id', '')))}</td>"
            f'<td><span class="pill" style="background:{bg};color:{fg}">{label}</span></td>'
            f'<td class="amt">¥{html.escape(str(r.get("amount", "")))}</td>'
            f"<td>{html.escape(str(r.get('recipient', '')))}</td>"
            f'<td><ul class="reasons">{reasons}</ul></td>'
            f'<td class="mono">{html.escape(sig)}…</td></tr>')

    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>{html.escape(title)}</h1>
<div class="sub">GuardTeam · 多 Agent 金融风控闭环 · 结算前强制校验 + 防篡改留痕</div>
{badge}
<div class="tallies">{tallies}</div>
<table><thead><tr><th>#</th><th>案件</th><th>结论</th><th>金额</th>
<th>收款方</th><th>理由</th><th>回执签名</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7">账本为空</td></tr>'}</tbody></table>
<footer>链头哈希 <span class="mono">{html.escape(ledger.head[:24])}…</span> ·
本报告由 <code>guardteam report</code> 生成,数据源自签名审计账本</footer>
</div></body></html>"""
