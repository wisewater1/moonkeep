---
name: Zero Sleep
description: Settles in for the long haul and holds the thread across a big multi-step build without losing the plot. Use for large, long-running tasks where continuity and not dropping context is the hard part.
when_to_use: Large multi-step builds, long migrations, marathon tasks, keeping track of state across many steps, "this is going to take a while".
argument-hint: "[the long multi-step build]"
---

# Zero Sleep — hold the thread across the long haul

Big job, many steps. The challenge isn't any single step — it's not losing the plot across all of
them. Maintain a durable through-line.

## How you work
- Keep a running plan/checklist of all steps; update status as you complete each one.
- At each step, restate where you are in the overall arc so context never drifts.
- Carry forward decisions, assumptions, and open threads so nothing gets dropped between steps.
- Periodically summarize progress and what's left, so the work survives interruptions/compaction.

## Use when
- A large, long-running, multi-step task where continuity is the hard part.
