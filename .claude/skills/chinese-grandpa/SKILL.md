---
name: Chinese Grandpa
description: Compresses a long brief by translating it to Mandarin before fanning it out to sub-agents, cutting tokens while preserving exact intent. Use when dispatching long or repeated instructions to a fleet of sub-agents and the token bill keeps climbing.
when_to_use: Large multi-agent / sub-agent runs with long shared instructions; batch jobs; fan-out where the same brief is sent to many agents and token cost matters.
argument-hint: "[the brief to compress + dispatch]"
---

# Chinese Grandpa — Mandarin prompt compression for sub-agent fleets

Frugal with tokens like grandpa is frugal with money: say the same thing with fewer characters.
When this mode is active, before you fan instructions out to sub-agents you first translate the
brief into terse, faithful **Mandarin Chinese** and dispatch *that* as the agent prompt.

## How you work
1. Take the brief (the `$ARGUMENTS` text, or the instructions about to be sent to sub-agents).
2. Translate the prose/instructions into compact Mandarin that preserves 100% of the intent —
   every requirement, constraint, and acceptance criterion. Lossless, not a summary.
3. Keep verbatim (do NOT translate): code, file paths, identifiers, API/function/variable names,
   CLI commands, URLs, error strings, and proper nouns.
4. Use the Mandarin version as the prompt when spawning each sub-agent (Task/Agent/Workflow).
5. Sub-agents may reason and reply in whatever language is natural; their *deliverables* (code,
   diffs, answers) stay in the original language/format.
6. Before dispatching, sanity-check the translation round-trips to the original intent. If any
   nuance is at risk, keep that clause in English rather than lose meaning.

## Use when
- You're pushing long, repeated instructions to many sub-agents and want to cut token cost.
- A big fan-out where the shared brief dominates the token budget.

## Notes
- The token win depends on the tokenizer; treat it as an optimization, not a guarantee. Fidelity
  of intent always wins over squeezing characters — never drop a requirement to save tokens.
