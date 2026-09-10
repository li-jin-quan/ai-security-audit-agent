"""AI 安全审计 agent — 规则引擎 (MVP)

每个规则是一个纯函数:
    def rule_name(filepath: str, lines: list[str]) -> list[Finding]

Finding 是简单 dict，字段:
    rule, file, line(1-based), snippet, severity, note

severity 取值: info < low < medium < high
MVP 阶段所有发现都标 info/low（候选），最终是否真漏洞由人/AI triage 决定。
这是"AI 闭环挖洞"的第一步：脚本出候选，人/AI 分析改脚本，迭代。
"""

from dataclasses import dataclass, asdict
import re

EXT_LANG = {
    ".rs": "rust",
    ".h": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".py": "python",
}


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    snippet: str
    severity: str
    note: str

    def to_dict(self):
        return asdict(self)


# 附近窗口内若出现这些关键字，认为"已做检查"，不报候选
_SIGN_CHECK_HINTS = (
    "if", "checked_", "saturating", "bail!", "assert", "any(|d|",
    "d.size < 0", "< 0", ">= 0", "try_into", "checked_mul", "checked_add",
)


def _nearby_has_check(lines, idx, window=3):
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window + 1)
    chunk = "\n".join(lines[lo:hi]).lower()
    return any(h.lower() in chunk for h in _SIGN_CHECK_HINTS)


def rust_as_usize_no_check(filepath, lines):
    """Rust 窄化转换 (as usize/u64/u32/i64...) 前无符号/边界检查 -> 候选。"""
    findings = []
    pat = re.compile(r"\bas\s+(u|i)(8|16|32|64|size|128)\b")
    for i, ln in enumerate(lines):
        if pat.search(ln) and not _nearby_has_check(lines, i):
            findings.append(Finding(
                rule="rust_as_usize_no_check",
                file=filepath,
                line=i + 1,
                snippet=ln.strip()[:160],
                severity="low",
                note="窄化转换前未见 sign/边界检查，构造负 dims 可能越界/崩溃（CWE-190/195/248）。需人工确认上下文。",
            ))
    return findings


def onnx_adapter_no_assert(filepath, lines):
    """ONNX adapter 对 inputs()[N] 索引前无 assertInputsAvailable/ONNX_ASSERTM -> 候选。

    限定：只在路径含 'onnx' 的 cpp 文件触发，避免跨仓误报（如 clippy 的 tcx.inputs()）。
    """
    if "onnx" not in filepath.lower():
        return []
    findings = []
    idx_pat = re.compile(r"inputs\(\)\s*\[|\binputs\(\s*\d+\s*\)")
    assert_pat = re.compile(r"assertInputsAvailable|ONNX_ASSERTM|onnx_runtime_assert")
    for i, ln in enumerate(lines):
        if idx_pat.search(ln):
            # 向上找所属函数开头，检查该函数是否做过 assert
            func_top = i
            for j in range(i, max(-1, i - 60), -1):
                if re.match(r"\s*(void|Node|\w+::|\bstatic\b)", lines[j]) and "{" in lines[j]:
                    func_top = j
                    break
            body = "\n".join(lines[func_top:i + 1])
            if not assert_pat.search(body):
                findings.append(Finding(
                    rule="onnx_adapter_no_assert",
                    file=filepath,
                    line=i + 1,
                    snippet=ln.strip()[:160],
                    severity="low",
                    note="对 inputs() 索引前未找到 assertInputsAvailable/ONNX_ASSERTM，恶意模型可能 NPD/OOB。需人工确认。",
                ))
    return findings


_EXTERNAL_PARSE_FILE = re.compile(r"(loader|parse|adapter|tensor|external|import)", re.I)


def panic_on_external_parse(filepath, lines):
    """解析外部/不可信数据路径上的 unwrap/expect/panic -> 候选（CWE-248 类）。"""
    findings = []
    if not _EXTERNAL_PARSE_FILE.search(filepath):
        return findings
    panic_pat = re.compile(r"\.unwrap\(\)|\.expect\(|panic!")
    for i, ln in enumerate(lines):
        if panic_pat.search(ln) and not _nearby_has_check(lines, i):
            findings.append(Finding(
                rule="panic_on_external_parse",
                file=filepath,
                line=i + 1,
                snippet=ln.strip()[:160],
                severity="info",
                note="解析外部数据路径上出现 unwrap/expect/panic，畸形输入可 panic（CWE-248）。需人工确认是否应转 error。",
            ))
    return findings


# ---- V2.1 新增：预分配/切片信任外部长度（CWE-770 / CWE-125/789） ----------

# 分配/切片前若附近出现这些"上限或校验"信号，则认为已做检查。
_ALLOC_HINTS = (
    "min(", "checked_", "saturating", "bail!", "take(", "limit", "max_len",
    "truncate", "if ", "< ", "resize(", "reserve(",
)


def _nearby_has_alloc_check(lines, idx, window=3):
    lo = max(0, idx - window)
    hi = min(len(lines), idx + window + 1)
    chunk = "\n".join(lines[lo:hi]).lower()
    return any(h.lower() in chunk for h in _ALLOC_HINTS)


_ALLOC_PAT = re.compile(
    r"(Vec::with_capacity|String::with_capacity|with_capacity)\s*\(")


def rust_with_capacity_untrusted(filepath, lines):
    """with_capacity(外部来的长度) 且附近无上限检查 -> 无界分配候选 (CWE-770)。

    对应实战：candle pickle BinUnicode / npy header_size、hf-hub
    download_file_to_bytes 的 Content-Length 预分配（均已提 PR）。
    """
    findings = []
    for i, ln in enumerate(lines):
        if _ALLOC_PAT.search(ln) and not _nearby_has_alloc_check(lines, i):
            # 参数里没有变量（纯字面量）不算
            arg = ln.split("(", 1)[1].split(")", 1)[0] if "(" in ln and ")" in ln else ""
            if arg and not re.search(r"[a-zA-Z_]", arg):
                continue
            findings.append(Finding(
                rule="rust_with_capacity_untrusted",
                file=filepath,
                line=i + 1,
                snippet=ln.strip()[:160],
                severity="low",
                note="with_capacity 参数疑似来自外部输入且附近未见上限检查，恶意文件可触发无界分配（CWE-770）。需人工确认长度来源。",
            ))
    return findings


_SLICE_PAT = re.compile(r"&[\w\.\(\)]*\[[^\]]*\.\.[^\]]*\]")


def rust_slice_range_no_bound(filepath, lines):
    """外部解析路径上 &data[a..b] 切片端点含变量且无边界检查 -> OOB 候选 (CWE-125/789)。

    限定文件路径含解析特征（loader/parse/adapter/tensor/...），压误报。
    对应实战：tract NNEF dims 乘加后切片（GHSA-6ffw-f7m6-gpxj 同族）。
    """
    if not _EXTERNAL_PARSE_FILE.search(filepath):
        return []
    findings = []
    for i, ln in enumerate(lines):
        m = _SLICE_PAT.search(ln)
        if not m or _nearby_has_alloc_check(lines, i):
            continue
        rng = m.group(0)
        # 取 [..] 内部，按 ".." 拆端点；两端均为纯数字的固定切片不算
        inner_m = re.search(r"\[([^\]]*)\]", rng)
        if not inner_m:
            continue
        parts = [p.strip() for p in inner_m.group(1).split("..")]
        if len(parts) != 2 or all(p.isdigit() for p in parts):
            continue
        if not re.search(r"[a-zA-Z_]", rng.replace("&", "").replace("[", "").replace("]", "")):
            continue
        findings.append(Finding(
            rule="rust_slice_range_no_bound",
            file=filepath,
            line=i + 1,
            snippet=ln.strip()[:160],
            severity="low",
            note="外部解析路径上变量端点切片且附近未见边界检查，畸形输入可 OOB/越界分配（CWE-125/789）。需人工确认。",
        ))
    return findings


# 规则注册表：config.rules 里的名字 -> 函数
REGISTRY = {
    "rust_as_usize_no_check": rust_as_usize_no_check,
    "onnx_adapter_no_assert": onnx_adapter_no_assert,
    "panic_on_external_parse": panic_on_external_parse,
    "rust_with_capacity_untrusted": rust_with_capacity_untrusted,
    "rust_slice_range_no_bound": rust_slice_range_no_bound,
}

# 每条规则的适用语言（run.py 调用前据此过滤，避免跨语言误报）。
# "any" 表示不限制语言（规则内部自行兜底）。
RULE_LANG = {
    "rust_as_usize_no_check": "rust",
    "onnx_adapter_no_assert": "cpp",
    "panic_on_external_parse": "any",
    "rust_with_capacity_untrusted": "rust",
    "rust_slice_range_no_bound": "rust",
}
