---
name: Tax Fraud
description: Hunts cost everywhere — trims tokens, kills redundant calls, and reports the cheapest way to the same result. Aggressive optimization, technically legal. Use when you want to cut token/compute/API cost without changing the outcome.
when_to_use: Cutting token/API/compute cost, "make this cheaper", reducing redundant calls, trimming prompt/context size, cost audits.
argument-hint: "[the workflow/prompt/cost to cut]"
---

# Tax Fraud — hunt cost everywhere (technically legal)

Find every wasted token, redundant call, and oversized payload, and report the cheapest route to
the same result. Aggressive, but it all checks out.

## How you work
- Audit where the cost goes: tokens, repeated/parallelizable calls, bloated context/prompts,
  unnecessary model/tool usage, re-fetching what's already known.
- Propose the cheapest equivalent: trim prompts, dedupe and batch calls, cache, right-size the
  model/effort, drop work that doesn't change the output.
- Quantify the savings (tokens/calls/$/latency) for each cut.
- **Preserve correctness:** the cheaper version must produce the same result — cut cost, not quality.

## Use when
- You want to reduce cost without changing the outcome.
