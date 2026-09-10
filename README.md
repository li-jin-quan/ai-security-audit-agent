# AI 安全审计 agent（MVP）

> 把 tract 挖洞方法论（无 sign check 的窄化转换 / 无边界检查的 parser 索引）固化为可复用静态审计工具链。
> 这是「AI 安全创业」方向的核心产品雏形 —— 防御侧，合法合规。

## 定位

- **是什么**：静态代码审计器，扫描 Rust / C++ / Python 源码中"解析不可信数据时的不安全模式"，输出机器可读(JSON) + 人类可读(Markdown) 双格式报告。
- **不是什么**：❌ 攻击工具、❌ 漏洞利用生成器、❌ 扫描器以外的主动攻击。纯防御侧。
- **为什么做**：你挖 tract 漏洞的路子（grep 无 sign check → 构造 PoC → 提 PR）是可复制的方法论。把它产品化 = 你的差异化壁垒（白帽 + 系统级 + Rust + AI Native 全串起来），且海外/不卡学历阵地认这种"作品"。

## 红线（铁律，不可越）

1. 只产出**候选发现** + **修复建议**，绝不生成可利用的攻击 payload。
2. 所有发现必须标注"待 triage 候选，非已确认漏洞"。
3. 对外材料只写"审计工具 / 防御能力"，不夸大战绩。

## 架构（对标 butian_tool 规范）

```
ai_audit_agent/
├── config.yaml          # 配置驱动：扫描目标 / 启用规则 / 输出格式
├── run.py               # 入口（零依赖，python run.py 即跑）
├── rules.py             # 规则引擎：每条规则 = (file, lines) -> [Finding]
├── reporter.py          # 报告层：JSON + Markdown 双输出
└── output/              # 扫描报告（时间戳命名）
```

## 内置规则（MVP）

| 规则 | 语言 | 检测模式 | 关联 CWE |
|------|------|----------|----------|
| `rust_as_usize_no_check` | Rust | `as usize/u64/u32` 窄化转换前无 sign/边界检查 | CWE-190/195/248 |
| `onnx_adapter_no_assert` | C++ | ONNX adapter 对 `inputs()[N]` 索引前无 `assertInputsAvailable` | CWE-129/476 |
| `panic_on_external_parse` | 任意 | 解析外部数据路径上的 `unwrap/expect/panic` | CWE-248 |

## 用法

```bash
# 用 managed python（无需 pip install，已内置 yaml 兜底）
C:/Users/EchoLi/.workbuddy/binaries/python/versions/3.13.12/python.exe run.py --config config.yaml

# 临时单目标 + 单规则
python run.py --target /path/to/tract --lang rust --rule rust_as_usize_no_check
```

## 实测（2026-09-09 首跑）

- 扫描 tract 仓库 967 文件 → 1429 候选
- 精准命中 `cli/src/compare.rs:233` 等 `as usize` 无 sign check 位置
- 已修复的 `onnx/src/tensor.rs` / `tflite/src/tensors.rs` 因带 `bail!` 检查被正确排除（不误报）

## 路线图（军师排兵）

1. **MVP（当前）**：规则驱动静态扫描，人工 triage。
2. **V2**：接 LLM 自动 triage —— 把 JSON 报告丢给 AI，AI 判断真漏洞/误报，生成最小修复 diff + PR 草稿。
3. **V3（完整 agent）**：定时扫描指定 OSS 仓库 → 自动发现候选 → AI 分析 → 生成修复 PR。= "AI 安全审计机器人"。

> V2/V3 的"AI 闭环"正是用户工具开发约定里的：脚本跑 → 结构化 log → AI 分析改脚本 → 继续跑。

## V2 已实现（2026-09-09）

把「候选 → 判定 → PR 草稿」闭环打通，仍纯防御侧、零攻击能力。

### 新增模块
- `triage.py`：TriageProvider 抽象 + 两个实现
  - `HeuristicProvider`：本地启发式打分（rule 基线 + snippet 上下文关键字），零依赖零网络，**必定可用**
  - `LLMProvider`：可选增强，调 DeepSeek / OpenAI 兼容 `/chat/completions`；**无 key / 网络失败自动降级 Heuristic**，绝不阻塞
  - `triage_or_save()`：工厂，按 `config.llm.enabled` 选路，保证必有结果
- `reporter.py` 升级：`write_triage_reports()`（triage JSON+MD，按 confidence 降序）+ `write_pr_drafts()`（top-K 修复建议草稿）
- `run.py` 串联：扫描 → 候选 → triage → 三份报告（audit / triage / pr_draft）
- `config.yaml` 加 `llm:` + `triage:` 两段

### 输出（每次运行 4 份）
1. `audit_*.json / .md` — 候选发现（MVP 原样，向后兼容）
2. `triage_*.json / .md` — 每个候选的 verdict / confidence / cwe / fix_suggestion
3. `pr_draft_*.md` — top-K 修复建议草稿（默认 15）

### 红线（铁律，V2 仍严守）
1. 只产出候选 + 判定 + 修复建议，**绝不生成可利用 payload**
2. PR 草稿 = 建议文本，**agent 不自动改仓库、不调 git**，需人工 review
3. 所有判定标注 confidence + verdict，非绝对结论
4. LLM prompt 强制"只判定 + 给修复建议，禁攻击代码"

### 启用真 LLM triage
```bash
# 配置环境变量后改 config.yaml: llm.enabled: true
export DEEPSEEK_API_KEY=sk-xxx
```
无 key 时默认走 Heuristic，功能完整不报错。

### 实测（2026-09-09）
`python run.py --target /path/to/tract --lang rust` → 967 文件 / 1429 候选 / triage 全 needs_review / PR 草稿 top15 生成成功。
