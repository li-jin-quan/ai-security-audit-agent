#!/usr/bin/env python3
"""AI 安全审计 agent — MVP 入口

把 tract 挖洞方法论固化为可复用静态审计工具链（纯防御侧）。
配置驱动 (config.yaml) + 规则引擎 (rules.py) + 报告层 (reporter.py)。

用法:
    python run.py --config config.yaml
    python run.py --target /path/to/tract --lang rust --rule rust_as_usize_no_check
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rules import REGISTRY, EXT_LANG, RULE_LANG  # noqa: E402
from reporter import write_reports, write_triage_reports, write_pr_drafts  # noqa: E402
from triage import triage_or_save      # noqa: E402

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


# ---- 零依赖 yaml 兜底（仅服务本工具固定格式 config） ----------------------
def _parse_scalar(s):
    s = s.strip()
    if "#" in s:  # 去掉行内注释（本工具 config 不含引号内的 #）
        s = s.split("#", 1)[0].strip()
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return [x.strip() for x in inner.split(",")] if inner else []
    if (len(s) >= 2) and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    return s


def _parse_dict(lines):
    d = {}
    for ln in lines:
        if ":" in ln and not ln.strip().startswith("- "):
            k, v = ln.split(":", 1)
            d[k.strip()] = _parse_scalar(v)
    return d


def _parse_block(lines):
    if any(ln.strip().startswith("- ") for ln in lines):
        items, i = [], 0
        while i < len(lines):
            ln = lines[i]
            if ln.strip().startswith("- "):
                content = ln.strip()[2:]
                ind = len(ln) - len(ln.lstrip())
                if ":" in content:
                    sub, j = [], i + 1
                    while j < len(lines) and (len(lines[j]) - len(lines[j].lstrip())) > ind:
                        sub.append(lines[j])
                        j += 1
                    d = _parse_dict(sub)
                    k, v = content.split(":", 1)
                    d[k.strip()] = _parse_scalar(v)
                    items.append(d)
                    i = j
                else:
                    items.append(_parse_scalar(content))
                    i += 1
            else:
                i += 1
        return items
    return _parse_dict(lines)


def _mini_yaml(text):
    lines = [l for l in text.splitlines() if l.strip()]
    root, i = {}, 0
    while i < len(lines):
        ln = lines[i]
        ind = len(ln) - len(ln.lstrip())
        if ind == 0 and ":" in ln and not ln.strip().startswith("- "):
            key = ln.split(":", 1)[0].strip()
            block, j = [ln], i + 1
            while j < len(lines) and (len(lines[j]) - len(lines[j].lstrip())) > ind:
                block.append(lines[j])
                j += 1
            rest = block[1:]
            root[key] = _parse_block(rest) if rest else None
            i = j
        else:
            i += 1
    return root


def _load_config(path):
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except ImportError:
        with open(path, "r", encoding="utf-8") as fh:
            return _mini_yaml(fh.read())


def _walk(target, langs):
    """yield (abspath, lang) for matched source files."""
    for root, _, files in os.walk(target):
        # 跳过明显非审计目标
        if any(s in root for s in ("/target/", "\\target\\", "/.git/", "\\.git\\", "/node_modules/", "\\node_modules\\")):
            continue
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            lang = EXT_LANG.get(ext)
            if lang and (not langs or lang in langs):
                yield os.path.join(root, fn), lang


def run(targets, rules, min_sev="info"):
    findings = []
    files_scanned = 0
    known = [r for r in rules if r in REGISTRY]
    for bad in set(rules) - set(known):
        print(f"[warn] 未知规则，跳过: {bad}", file=sys.stderr)
    rules = known
    for target in targets:
        path, langs = target["path"], target.get("languages", [])
        if not os.path.isdir(path):
            print(f"[warn] 目标不存在，跳过: {path}", file=sys.stderr)
            continue
        for fp, lang in _walk(path, langs):
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except Exception:
                continue
            files_scanned += 1
            for rname in rules:
                rule_fn = REGISTRY.get(rname)
                if not rule_fn:
                    print(f"[warn] 未知规则: {rname}", file=sys.stderr)
                    continue
                rule_lang = RULE_LANG.get(rname, "any")
                if rule_lang != "any" and lang != rule_lang:
                    continue  # 跨语言不跑，避免误报（如 cpp 规则扫 rust 仓）
                try:
                    findings.extend(rule_fn(fp, lines))
                except Exception as e:  # 单文件失败不中断整体
                    print(f"[warn] {rname} 处理 {fp} 失败: {e}", file=sys.stderr)
    stats = {"files_scanned": files_scanned, "rules": rules}
    return findings, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"))
    ap.add_argument("--target", help="临时单目标路径（覆盖 config 的 scan_targets）")
    ap.add_argument("--lang", help="临时语言过滤，如 rust")
    ap.add_argument("--rule", help="临时单规则名（覆盖 config 的 rules）")
    args = ap.parse_args()

    config = _load_config(args.config)

    if args.target:
        targets = [{"path": args.target, "languages": [args.lang] if args.lang else []}]
    else:
        targets = config.get("scan_targets", [])

    if args.rule:
        rules = [args.rule]
    else:
        rules = config.get("rules", list(REGISTRY.keys()))

    min_sev = config.get("output", {}).get("min_severity", "info")

    print(f"[*] 扫描目标: {len(targets)} | 规则: {rules} | 阈值: {min_sev}")
    findings, stats = run(targets, rules, min_sev)
    jp, mp = write_reports(findings, config, stats)

    # V2: 自动 triage + PR 草稿
    triage_results = triage_or_save(findings, config)
    tjp, tmp = write_triage_reports(triage_results, findings, config, stats)
    pp = write_pr_drafts(triage_results, config)

    print(f"[+] 扫描文件: {stats['files_scanned']} | 候选发现: {len(findings)}")
    if jp:
        print(f"[+] JSON 报告: {jp}")
    if mp:
        print(f"[+] MD  报告: {mp}")
    print(f"[+] Triage 报告: {tjp}")
    print(f"[+] PR 草稿: {pp}")
    print("[*] 提示: 所有发现均为待 triage 候选，非已确认漏洞。triage 判定需人工 review。")


if __name__ == "__main__":
    main()
