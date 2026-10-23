"""report.md: deterministic findings first; model explanations are labeled and never contain commands.
Info findings appear only as counts per check; full detail stays in findings.json."""
from collections import Counter

from .findings import SEVERITIES

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "⚪"}
RANK = {s: i for i, s in enumerate(SEVERITIES)}


def _md(s: str) -> str:
    return str(s).replace("`", "'").replace("|", "/")


def _fix_line(cmd: str) -> str:
    # shlex.quote keeps the shell safe but not the markdown: a newline in a path would forge a line
    if cmd.isprintable() and "`" not in cmd:
        return f"- Виправлення: `{cmd}`"
    return "- Виправлення: (команду не показано: керівні символи в шляху, див. findings.json)"


def _info_line(items) -> list:
    c = Counter(f.check for f in items if f.severity == "info")
    if not c:
        return []
    parts = ", ".join(f"{n} × {_md(k)}" for k, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))
    return [f"- {ICON['info']} info: {parts}", ""]


def render(run_id, new, open_items, accepted, resolved, results, triage, triage_error, one_off=False) -> str:
    tri = (triage or {}).get("items", {})
    lines = [f"# Mac security — {run_id}", ""]
    if one_off:
        lines += ["> Разова перевірка (`msec scan`): без baseline, тому все знайдене показано як нове.", ""]
    if triage and triage.get("overview"):
        lines += ["## Огляд (пояснення моделі, не інструкції)", "", _md(triage["overview"]), ""]
    elif triage_error:
        lines += [f"> Аналіз моделлю не виконано: {_md(triage_error)}. Знахідки нижче повні.", ""]

    def block(title, items):
        lines.extend([f"## {title} ({len(items)})", ""])
        for f in sorted((x for x in items if x.severity != "info"), key=lambda x: RANK[x.severity]):
            lines.append(f"### {ICON[f.severity]} {_md(f.title)}")
            lines.append(f"- `{f.fingerprint}` · {f.check} · {f.category}")
            t = tri.get(f.fingerprint)
            if t:
                lines.append(f"- Модель: {_md(t['explanation'])}{' (ймовірно безпечно)' if t['likely_benign'] else ''}")
            lines.extend(_fix_line(cmd) for cmd in f.fix)
            lines.append("")
        lines.extend(_info_line(items))

    block("Нове", new)
    if not one_off:
        block("Відкриті критичні", [f for f in open_items if f.severity == "critical"])
        rest = sorted((f for f in open_items if f.severity != "critical"), key=lambda x: RANK[x.severity])
        lines += [f"## Відкриті, дайджест ({len(rest)})", ""]
        lines += [f"- {ICON[f.severity]} `{f.fingerprint}` {_md(f.title)}" for f in rest if f.severity != "info"] + [""]
        lines += _info_line(rest)
    ns = [r for r in results if r.status == "not_scanned"]
    lines += [f"## Не перевірено ({len(ns)})", ""] + [f"- {r.check}: {_md(r.reason)}" for r in ns] + [""]
    if not one_off:
        lines += [f"Прийнято: {len(accepted)} · Зникло з минулого разу: {len(resolved)}", "",
                  'Прийняти знахідку: `msec accept <fingerprint> --reason "..." --days 90`', ""]
    return "\n".join(lines)
