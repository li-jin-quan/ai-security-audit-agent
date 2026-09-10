# AI Security Audit Agent

Static audit agent for AI/ML inference supply chains. It encodes a repeatable
vulnerability-hunting methodology — unchecked narrowing casts, unvalidated
parser indices, panic-on-parse paths — into a reusable, config-driven audit
pipeline for Rust / C++ / Python codebases.

> **Defensive tooling only.** The agent produces candidate findings, triage
> verdicts and fix suggestions. It never generates exploit payloads.

## Why

Modern ML runtimes parse untrusted files (model weights, checkpoints,
tokenizers) from the internet. Several real bug classes keep reappearing in
this supply chain:

- Unchecked narrowing casts (`as usize`) on attacker-controlled lengths
- Parsers that allocate or index before validating input
- `unwrap`/`expect` on external data paths

This project turns the manual hunt-and-fix workflow into a pipeline:
**scan → candidates → triage → reports / PR drafts.**

## Architecture

```
ai-security-audit-agent/
├── config.yaml   # scan targets, enabled rules, output formats
├── run.py        # entry point (zero-dependency, no pip install needed)
├── rules.py      # rule engine: (file, lines) -> [Finding]
├── triage.py     # HeuristicProvider (default) + optional LLM provider
├── reporter.py   # JSON + Markdown reports, PR draft generation
└── output/       # timestamped scan reports (gitignored)
```

## Built-in rules (MVP)

| Rule | Language | Detects | CWE |
|------|----------|---------|-----|
| `rust_as_usize_no_check` | Rust | narrowing casts without sign/bounds check | CWE-190/195/248 |
| `onnx_adapter_no_assert` | C++ | `inputs()[N]` indexing without `assertInputsAvailable` | CWE-129/476 |
| `panic_on_external_parse` | any | `unwrap`/`expect` on untrusted parse paths | CWE-248 |

## Usage

```bash
# full pipeline with config
python run.py --config config.yaml

# single target + single rule
python run.py --target /path/to/repo --lang rust --rule rust_as_usize_no_check
```

Each run produces four reports in `output/`:

1. `audit_*.json / .md` — raw candidate findings
2. `triage_*.json / .md` — per-candidate verdict / confidence / CWE / fix suggestion
3. `pr_draft_*.md` — top-K fix-suggestion drafts for human review

## Triage

- **HeuristicProvider** (default): local scoring, zero dependencies, always available.
- **LLMProvider** (optional): OpenAI-compatible `/chat/completions` (tested with
  DeepSeek). Falls back to Heuristic automatically when no key is set or the
  network fails.

```bash
export DEEPSEEK_API_KEY=sk-...   # then set llm.enabled: true in config.yaml
```

## Field test

First run against a large Rust inference framework (~967 files): **1,429
candidates**, correctly pinpointing unchecked `as usize` sites (e.g.
`compare.rs:233`) while excluding already-guarded paths (no false positives
on fixed files).

## Track record

The methodology encoded here is the same one behind these upstream fixes:

- **sonos/tract** — 3 merged security PRs ([#2766](https://github.com/sonos/tract/pull/2766),
  [#2795](https://github.com/sonos/tract/pull/2795), [#2796](https://github.com/sonos/tract/pull/2796)),
  plus open PRs including [#2814](https://github.com/sonos/tract/pull/2814)
- **GHSA-6ffw-f7m6-gpxj** — unbounded allocation in tract's NNEF loader
  (CVE assignment pending, accepted by the maintainer)
- Open PRs on **huggingface/candle** ([#3961](https://github.com/huggingface/candle/pull/3961),
  [#3962](https://github.com/huggingface/candle/pull/3962)) and
  **huggingface/hf-hub** ([#202](https://github.com/huggingface/hf-hub/pull/202))

All findings are disclosed responsibly via upstream patches.

## Roadmap

1. **MVP** (done) — rule-driven static scan, manual triage
2. **V2** (done) — automated triage + fix-suggestion / PR-draft generation
3. **V3** — scheduled scans of watchlisted repos → automated candidate
   discovery → AI analysis → fix PRs: a self-running audit bot

## License

MIT
