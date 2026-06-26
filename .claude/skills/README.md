# Named-mode skills

25 Claude Code skills. Each is a memorable name wrapped around a real working mode — the name is
the joke, the saved time is the point. Invoke any of them with `/<name>`, or let Claude apply one
automatically when your request matches its description (auto-trigger is enabled).

Each skill lives in its own directory as `SKILL.md`. They follow the
[Agent Skills](https://code.claude.com/docs/en/skills) format.

## Install everywhere (all your projects)

These ship as **project skills** here (active in this repo). To make them available across *every*
project, install them as personal skills:

```bash
bash install-skills.sh            # copy into ~/.claude/skills/
bash install-skills.sh --symlink  # symlink instead, so repo edits stay live
```

Then **restart Claude Code** once — a newly created top-level `~/.claude/skills/` directory is only
watched after a restart.

## The 25

### Headliners
| Command | What it does |
| --- | --- |
| `/chinese-grandpa` | Translates a long brief to Mandarin before fanning out to sub-agents, to cut tokens while preserving intent. |
| `/weaponized-autism` | Obsessive, exhaustive audit/debug mode — checks everything, verifies every claim, hard to fool. |
| `/meth-lab` | Workflow/cost optimizer — strips a messy/slow/expensive system to the lean version that still works. |
| `/divorced-dad` | Stops gold-plating — ships the simplest working version today. |
| `/redneck-engineer` | Turns a fuzzy idea into a build spec: PRD, tasks, flows, constraints, acceptance criteria. |

### Ship It Anyway — scrappy execution
| Command | What it does |
| --- | --- |
| `/duct-tape-dev` | Quick patch that unblocks now, clearly flagged as debt. |
| `/gas-station-genius` | Solves it with only what's already in the repo — no new deps. |
| `/macgyver` | Improvises from primitives and the standard library instead of a new framework. |
| `/apollo-13` | Recovers a critical failure under hard constraints with what's on hand. |
| `/cowboy-coder` | Makes the calls itself and keeps moving; best on low-stakes work. |
| `/questionable-engineering` | Picks what works over what's technically correct; for prototypes. |
| `/goblin-mode` | Gets it working ugly first; structure only once it earns its place. |

### Full Send — speed, chaos, endurance
| Command | What it does |
| --- | --- |
| `/speedrun` | Shortest path to done; no detours. |
| `/autopilot-chaos` | Runs the whole task end to end; you review at the finish line. |
| `/rage-compile` | Fix, rebuild, repeat until it builds clean. |
| `/panic-mode` | Incident triage: stop the bleeding, smallest safe fix, then post-mortem. |
| `/zero-sleep` | Holds the thread across a big multi-step build. |
| `/sleep-deprived-founder` | Cuts the backlog to the 1–2 things that move the needle. |
| `/crackhead-energy` | ~20 rough ideas fast; you cherry-pick. |
| `/caffeine-overdose` | Wide and exhaustive; every option and edge spelled out. |

### Feral Focus — heads-down, deep digs, cost hacks
| Command | What it does |
| --- | --- |
| `/feral-goblin` | No small talk; just code and short status lines. |
| `/keyboard-gremlin` | Smallest possible change; minimal diff. |
| `/basement-hacker` | Reverse-engineers internals; reads the source nobody reads. |
| `/schizotech` | Wild lateral architecture ideas (filter heavily). |
| `/tax-fraud` | Hunts cost everywhere; cheapest path to the same result. |

## Notes
- **Auto-trigger:** a few modes are aggressive to auto-apply (`autopilot-chaos`, `cowboy-coder`,
  `crackhead-energy`). To make any one manual-only, add `disable-model-invocation: true` to its
  frontmatter — it still appears in the `/` menu.
- `/chinese-grandpa`'s token savings depend on the tokenizer and aren't guaranteed; intent fidelity
  always wins over squeezing characters.
- Modes that act autonomously still pause before destructive/irreversible actions.
