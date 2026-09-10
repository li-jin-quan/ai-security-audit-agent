"""AI 安全审计 agent — V2 triage 模块

把 MVP 的「候选发现」升级为「带判定的报告」：
  - HeuristicProvider：本地启发式，零依赖零网络，必定可用
  - LLMProvider：可选增强，调 DeepSeek / OpenAI 兼容 API；无 key 或网络失败自动降级 Heuristic
  - 不生成任何攻击 payload；只产出 verdict + confidence + 修复建议（文本）
  - 不写回任何源文件、不调 git —— agent 只建议，人来决定

红线（不可越）：
  1. 绝不生成可利用的攻击代码 / payload
  2. 所有判定标注 confidence + verdict，非绝对结论
  3. PR 草稿 = 修复建议文本，不自动改仓库
"""
import os
import re
import sys
import json
import urllib.request
from dataclasses import dataclass, asdict

# --- 规则元数据：主 CWE + 修复建议模板 --------------------------------------
_RULE_META = {
    "rust_as_usize_no_check": {
        "cwe": "CWE-190",
        "fix": ("在该窄化转换前加符号/边界检查，例如 `if x < 0 { bail!(\"negative dim\") }` "
                "或改用 `try_into().map_err(|_| ...)?`。参考 tensorflow/src/tensor.rs:44 已有模式。"),
    },
    "onnx_adapter_no_assert": {
        "cwe": "CWE-129",
        "fix": ("在 `inputs()[N]` 索引前调用 `Node::assertInputsAvailable(inputs, N)` / `ONNX_ASSERTM`，"
                "确保模型确实提供了足够输入，避免 OOB / NPD。"),
    },
    "panic_on_external_parse": {
        "cwe": "CWE-248",
        "fix": ("将 `unwrap()/expect()/panic!` 改为错误传播（`?` 或 `TractResult`），"
                "畸形外部输入应返回错误而非进程 panic。"),
    },
}

_UP = re.compile(r"vec::with_capacity|\.resize\(|alloc|vec!|with_capacity|repeat\(", re.I)
_LOOP = re.compile(r"for\s+\w+\s+in|iter\(\)|collect\(|push\(", re.I)
_EXT = re.compile(r"loader|parse|import|tensor|adapter|external", re.I)
_TEST = re.compile(r"/test|/tests|/example|/examples|/bench|#\[test|#\[cfg\(test\)|panic::", re.I)
_SAFE = re.compile(r"//\s*safe|//\s*internal|unreachable!|debug_assert", re.I)


@dataclass
class TriageResult:
    rule: str
    file: str
    line: int
    verdict: str        # confirmed | false_positive | needs_review
    confidence: float   # 0..1
    cwe: str
    fix_suggestion: str
    provider: str       # heuristic | llm

    def to_dict(self):
        return asdict(self)


class TriageProvider:
    def triage(self, findings):
        raise NotImplementedError


class HeuristicProvider(TriageProvider):
    """本地启发式：基于 rule 基线 + snippet 上下文关键字打分。零依赖、零网络。"""
    def triage(self, findings):
        out = []
        for f in findings:
            meta = _RULE_META.get(f.rule, {"cwe": "CWE-UNKNOWN", "fix": "需人工审查上下文。"})
            base = {
                "rust_as_usize_no_check": 0.35,
                "onnx_adapter_no_assert": 0.50,
                "panic_on_external_parse": 0.45,
            }.get(f.rule, 0.30)
            score = base
            snip = f.snippet
            if _EXT.search(snip) or _EXT.search(f.file):
                score += 0.15
            if _UP.search(snip):
                score += 0.10
            if _LOOP.search(snip):
                score += 0.05
            if _TEST.search(snip) or _TEST.search(f.file):
                score -= 0.20
            if _SAFE.search(snip):
                score -= 0.15
            score = max(0.0, min(1.0, score))
            verdict = "false_positive" if score < 0.35 else "needs_review"
            out.append(TriageResult(
                rule=f.rule, file=f.file, line=f.line,
                verdict=verdict, confidence=round(score, 2),
                cwe=meta["cwe"], fix_suggestion=meta["fix"],
                provider="heuristic",
            ))
        return out


class LLMProvider(TriageProvider):
    """可选增强：调 DeepSeek / OpenAI 兼容 API。任何失败返回 None（由上层降级）。"""
    def __init__(self, cfg):
        self.cfg = cfg
        self.api_key = os.environ.get(cfg.get("api_key_env", ""), "")
        if not self.api_key:
            raise ValueError("llm.api_key_env 未设置或环境变量为空")

    def triage(self, findings):
        if not findings:
            return []
        top = int(self.cfg.get("max_candidates", 200))
        batch = findings[:top]
        sys_prompt = (
            "You are a defensive static-analysis triage assistant for a Rust/Python/C++ "
            "security audit tool. You receive candidate findings (each is a risky code pattern "
            "in a parser/loader that handles untrusted input). For each finding, output a JSON "
            "array. Each item: {\"rule\",\"file\",\"line\",\"verdict\":"
            "\"confirmed\"|\"false_positive\"|\"needs_review\",\"confidence\":0.0-1.0,"
            "\"cwe\":\"CWE-xxx\",\"fix_suggestion\":\"short English text\"}. "
            "RULES: (1) ONLY judge and suggest fixes. NEVER produce exploit code or payloads. "
            "(2) Be conservative: when unsure, use needs_review. (3) fix_suggestion must be a "
            "code-level remediation hint, not an attack."
        )
        payload_findings = [f.to_dict() for f in batch]
        user_prompt = json.dumps(payload_findings, ensure_ascii=False)
        body = json.dumps({
            "model": self.cfg.get("model", "deepseek-v4-flash"),
            "messages": [
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }).encode("utf-8")
        url = self.cfg.get("api_base", "https://api.deepseek.com").rstrip("/") + "/chat/completions"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {self.api_key}")
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        opener = urllib.request.build_opener()
        if proxy:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}))
        try:
            with opener.open(req, timeout=int(self.cfg.get("timeout", 30))) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            arr = json.loads(content)
            if isinstance(arr, dict):
                arr = arr.get("findings", arr.get("results", []))
            results = []
            for it in arr:
                results.append(TriageResult(
                    rule=it.get("rule", ""), file=it.get("file", ""),
                    line=int(it.get("line", 0)),
                    verdict=it.get("verdict", "needs_review"),
                    confidence=float(it.get("confidence", 0.5)),
                    cwe=it.get("cwe", "CWE-UNKNOWN"),
                    fix_suggestion=it.get("fix_suggestion", ""),
                    provider="llm",
                ))
            return results
        except Exception as e:  # 任何失败 -> 上层降级启发式
            print(f"[warn] LLM 调用失败: {e}", file=sys.stderr)
            return None


def triage_or_save(findings, config):
    """工厂：优先 LLM（若 enabled），失败/缺失则降级 Heuristic。保证必有结果。"""
    llm_cfg = config.get("llm") or {}
    enabled = llm_cfg.get("enabled", False)
    if isinstance(enabled, str):  # mini-yaml 兜底下 "false" 也是字符串
        enabled = enabled.strip().lower() in ("1", "true", "yes", "on")
    if enabled:
        try:
            res = LLMProvider(llm_cfg).triage(findings)
            if res is not None:
                return res
        except Exception as e:
            print(f"[warn] LLM triage 不可用，降级启发式: {e}", file=sys.stderr)
    return HeuristicProvider().triage(findings)
