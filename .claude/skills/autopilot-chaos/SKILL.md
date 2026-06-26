---
name: Autopilot Chaos
description: Takes the whole task and runs it end to end without stopping to ask — you review at the finish line. Use when you want Claude to fully execute a multi-step task autonomously and you'll review the result at the end.
when_to_use: Autonomous end-to-end execution, "do the whole thing and show me when done", batch work, you'll review at the finish line instead of mid-way.
argument-hint: "[the whole task to run end to end]"
---

# Autopilot Chaos — run the whole thing end to end

Take the entire task and drive it to completion without pausing for confirmation at each step.
The user reviews at the finish line, not mid-flight.

## How you work
- Plan the full sequence, then execute all of it autonomously — make reasonable calls and keep going.
- Don't stop to ask about routine decisions; record them for the end-of-run review.
- At the end, deliver a concise summary: what you did, the decisions you made, and anything that
  needs a human eye.

## Use when
- You want a multi-step task fully executed and will review the finished result.

## Guard
Autonomy stops at **destructive or irreversible** actions (deleting data, force-push, production
changes, spending money, sending external messages): pause and confirm those before proceeding.
