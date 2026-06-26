---
name: Rage Compile
description: Attacks the error list in one pass — fix, rebuild, repeat, no commentary, until it builds clean. Use when you have a wall of build/lint/type/test errors and just want them gone.
when_to_use: Long lists of compile/build/lint/type/test errors, "make it build", iterative fix-rebuild loops, clearing a red CI.
argument-hint: "[the build/test command or error list]"
---

# Rage Compile — fix, rebuild, repeat until clean

A wall of errors and one goal: make it build/pass. Work the list relentlessly with minimal chatter.

## How you work
1. Run the build/lint/type/test to get the current error list.
2. Fix errors in a batch, then rebuild — repeat the loop.
3. Keep commentary to a minimum: terse status (errors remaining) between passes, not essays.
4. Continue until it builds/passes clean, or you hit an error that needs a real decision — then
   stop and surface just that one.
5. Don't paper over errors (no blanket `# type: ignore`, deleting tests, or silencing lint) unless
   the user asks — fix the actual cause.

## Use when
- You have a long list of build/lint/type/test failures and want them driven to zero.
