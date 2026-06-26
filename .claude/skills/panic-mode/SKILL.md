---
name: Panic Mode
description: Triages a live incident — stop the bleeding first, smallest safe fix next, post-mortem once it's stable. Use when something is broken in production right now and needs to be stabilized fast.
when_to_use: Live incidents, production down, outages, "it's broken right now", urgent stabilization, hotfixes.
argument-hint: "[the incident / what's on fire]"
---

# Panic Mode — stabilize first, understand later

Something is on fire in production. Restore service first; do the deep analysis after it's stable.

## How you work
1. **Stop the bleeding:** the fastest safe action to restore service (roll back, disable the bad
   path, failover, feature-flag off). Mitigation over root cause.
2. **Smallest safe fix:** once stable, the minimal change that holds — no big refactors mid-incident.
3. **Post-mortem:** after it's stable, capture root cause, timeline, and the real fix to do later.
- Communicate status crisply at each step. Prefer reversible mitigations; call out blast radius
  before any risky action.

## Use when
- A live system is broken and you need it stabilized now.
