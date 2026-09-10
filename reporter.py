"""AI 安全审计 agent — 报告层

输出双格式：
  - JSON：机器可读，供 AI 下一轮 triage 消费
  - Markdown：人类可读，按文件分组，一键复制提交
"""

import json
import os
from datetime import datetime

from triage import TriageResult  # noqa: E402

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _filter(findings, min_sev):
    return [f for f in findings if SEV_ORDER.get(f.severity, 0) >= SEV_ORDER.get(min_sev, 0)]


def _group_by_file(findings):
    out = {}
    for f in findings:
        out.setdefault(f.file, []).append(f)
    return out


def write_reports(findings, config, stats):
    out_dir = config["output"]["dir"]
    os.makedirs(out_dir, exist_ok=True)
    min_sev = config["output"].get("min_severity", "info")
    kept = _filter(findings, min_sev)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan_stats": stats,
        "min_severity": min_sev,
        "total_findings": len(kept),
        "findings": [f.to_dict() for f in kept],
    }

    if "json" in config["output"]["formats"]:
        jp = os.path.join(out_dir, f"audit_{ts}.json")
        with open(jp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    else:
        jp = None

    if "markdown" in config["output"]["formats"]:
        mp = os.path.join(out_dir, f"audit_{ts}.md")
        _write_markdown(mp, kept, stats, min_sev)
    else:
        mp = None

    return jp, mp


def _write_markdown(path, findings, stats, min_sev):
    lines = []
    lines.append("# AI 安全审计 agent — 扫描报告\n")
    lines.append(f"- 生成时间: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- 扫描文件: {stats['files_scanned']} | 严重度阈值: {min_sev}")
    lines.append(f"- 候选发现: {len(findings)}（**均为待 triage 候选，非已确认漏洞**）\n")
    lines.append("---\n")

    grouped = _group_by_file(findings)
    for fp, items in sorted(grouped.items()):
        lines.append(f"\n## {fp}\n")
        for f in sorted(items, key=lambda x: x.line):
            lines.append(f"- **L{f.line}** `[{f.rule}]` ({f.severity})")
            lines.append(f"  ```")
            lines.append(f"  {f.snippet}")
            lines.append(f"  ```")
            lines.append(f"  > {f.note}\n")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ---- V2: triage 报告 + PR 草稿 -----------------------------------------
def _count_verdicts(results):
    c = {}
    for r in results:
        c[r.verdict] = c.get(r.verdict, 0) + 1
    return c


def write_triage_reports(triage_results, findings, config, stats):
    """V2: 把 triage 判定结果落 JSON + Markdown（按 confidence 降序）。"""
    out_dir = config["output"]["dir"]
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scan_stats": stats,
        "total_triage": len(triage_results),
        "verdicts": _count_verdicts(triage_results),
        "results": [r.to_dict() for r in triage_results],
    }
    jp = os.path.join(out_dir, f"triage_{ts}.json")
    with open(jp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    mp = os.path.join(out_dir, f"triage_{ts}.md")
    _write_triage_md(mp, triage_results, stats)
    return jp, mp


def _write_triage_md(path, results, stats):
    lines = []
    lines.append("# AI 安全审计 agent — Triage 报告 (V2)\n")
    lines.append(f"- 生成时间: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- 扫描文件: {stats['files_scanned']} | triage 候选: {len(results)}")
    counts = _count_verdicts(results)
    lines.append(f"- 判定分布: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    lines.append(f"- **所有判定均为 AI/启发式建议，非已确认漏洞，需人工 review**\n")
    lines.append("---\n")
    for r in sorted(results, key=lambda x: -x.confidence):
        lines.append(f"## [{r.verdict}] {r.file}:{r.line}")
        lines.append(f"- rule: `{r.rule}` | confidence: {r.confidence} | {r.cwe} | provider: {r.provider}")
        lines.append(f"- 修复建议: {r.fix_suggestion}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_pr_drafts(triage_results, config):
    """V2: 对 needs_review/confirmed 取 top-K（按 confidence），生成修复建议草稿。

    红线：本文件只给建议文本与位置，agent 不自动改仓库、不调 git。
    """
    out_dir = config["output"]["dir"]
    os.makedirs(out_dir, exist_ok=True)
    top_k = int(config.get("triage", {}).get("top_k", 15))
    cand = [r for r in triage_results if r.verdict in ("needs_review", "confirmed")]
    cand.sort(key=lambda x: -x.confidence)
    top = cand[:top_k]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    mp = os.path.join(out_dir, f"pr_draft_{ts}.md")
    lines = []
    lines.append("# AI 安全审计 agent — PR 草稿 (V2, 建议)\n")
    lines.append(f"- 生成时间: {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"- 本文件为**修复建议草稿**，agent 不自动改仓库、不调 git。需人工 review 后采用。\n")
    lines.append("---\n")
    for i, r in enumerate(top, 1):
        lines.append(f"## {i}. {r.file}:{r.line} — `{r.rule}`")
        lines.append(f"- verdict: {r.verdict} | confidence: {r.confidence} | {r.cwe}")
        lines.append(f"- 修复建议:")
        lines.append(f"  > {r.fix_suggestion}\n")
    with open(mp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return mp
