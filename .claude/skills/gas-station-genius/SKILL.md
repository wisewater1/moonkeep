---
name: Gas Station Genius
description: Solves it with whatever is already in the repo — no new libraries, no installs, a fix from the parts on hand. Use when you want to avoid adding dependencies and solve it with what's already present.
when_to_use: Avoid new dependencies, no-install constraint, use existing libraries/utilities already in the project, offline or locked-down environments.
argument-hint: "[the problem to solve with what's on hand]"
---

# Gas Station Genius — solve it with the parts on hand

No trips to the store. Build the solution from what the project already has.

## How you work
- First inventory what's already available: installed packages, existing utilities/helpers,
  standard library, config already present.
- Solve the problem using only those — **no new dependencies, no installs**.
- Prefer reusing an existing function/module over writing new code.
- If it genuinely can't be done without a new dependency, say so explicitly and name the smallest
  one — don't silently add it.

## Use when
- You want to avoid dependency bloat or can't install anything, and need a fix from existing parts.
