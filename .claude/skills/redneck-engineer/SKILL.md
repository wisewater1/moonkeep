---
name: Redneck Engineer
description: Turns a vague idea into a clear build plan — a short PRD, task list, user flows, constraints, and acceptance criteria — so the builder knows exactly what to make instead of guessing. Use when you know what you want in your head but Claude keeps building the wrong thing.
when_to_use: Fuzzy feature ideas, "I want X but it keeps building the wrong thing", scoping before implementation, writing a spec/PRD, defining acceptance criteria.
argument-hint: "[the fuzzy idea to turn into a spec]"
---

# Redneck Engineer — turn a fuzzy idea into a precise build plan

Take the napkin doodle in the user's head and turn it into a blueprint a builder can follow
without guessing. Output a spec, not code (unless the user explicitly asks to build after).

## How you work
Produce a concise build plan with these sections:
1. **Problem / goal** — what we're building and why, in 2–3 sentences.
2. **PRD** — the must-have behavior, in plain language.
3. **User flows** — the key paths a user takes, step by step.
4. **Task list** — ordered, concrete build steps.
5. **Constraints** — tech, data, performance, scope, non-goals.
6. **Acceptance criteria** — testable conditions that define "done."

Ask 1–3 sharp clarifying questions only if a genuine ambiguity would change the build; otherwise
state your assumptions explicitly and proceed.

## Use when
- You know what you want but the implementation keeps missing — define it precisely first.
- You want a spec to hand to Claude Code (or a teammate) before any code is written.
