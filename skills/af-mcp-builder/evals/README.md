# af-mcp-builder evals

Two kinds of evaluation live here.

- **Behaviour evals** (`evals.json`, `fixtures/`, `benchmark.json`): prompts with
  checkable assertions, run with and without the skill and graded by reading the
  final answer.
- **Trigger evals** (`trigger_queries.json`, `run_trigger_eval.py`,
  `score_trigger_results.py`, `trigger_results/`): whether Claude loads the skill
  for a query, which depends on the `description` in `SKILL.md`.

## Running the trigger eval

Needs the `claude` CLI (Claude Code) logged in. Run from the repository root.

```bash
# 1. Run every query 3 times against a candidate description. The description
#    is text or @file; --out receives per-query trigger counts.
python skills/af-mcp-builder/evals/run_trigger_eval.py \
    --queries skills/af-mcp-builder/evals/trigger_queries.json \
    --description @candidate.txt --runs 3 --out run1.json

# 2. Score it: recall, precision and F1 for the train and held-out splits.
python skills/af-mcp-builder/evals/score_trigger_results.py run1.json

# Repeat step 1 for more runs, then pool the files into one score.
python skills/af-mcp-builder/evals/score_trigger_results.py --pool run1.json run2.json
```

`trigger_queries.json` holds the queries with a fixed `train` / `test` split.
Write a description against the train split and report the test split; the split
is fixed so that candidates are compared on the same queries. Raw per-query
results of the descriptions tried so far are in `trigger_results/`.

Metrics are pooled over runs, not queries. A query that fires in 2 of 3 runs adds
2 true positives and 1 false negative when it should trigger, and 2 false
positives when it should not. The scorer also prints a Wilson 95% interval on
recall, because with a dozen positive queries the point estimate alone is loose.

## The positive control

Before trusting any number, check the harness can see the skill at all. Run the
harness on a query that names the skill outright and confirm it triggers:

```bash
echo '[{"id":"ctl","split":"test","should_trigger":true,"query":"use the af-mcp-builder skill to audit ./server.py"}]' > ctl.json
python skills/af-mcp-builder/evals/run_trigger_eval.py \
    --queries ctl.json --description @candidate.txt --runs 3 --out ctl_out.json
```

Every run must fire, and `visible` in `ctl_out.json` must be `true` (the session's
`init` event lists the skill). If the control does not trigger, the measurement is
broken and tuning the description cannot fix it.

## Why not skill-creator's `run_eval.py`

The stock harness under-measured this skill: the original description scored 3 of
24 held-out should-trigger runs there (recall 12%) and 24 of 24 here, and a
positive control that names the skill triggered in only 1 of 2 and 0 of 2 runs.
Three causes, each checked by reading its source:

1. **It does not test the skill.** It writes a throwaway command file named
   `<skill>-skill-<uuid>` under `.claude/commands` and detects a call to that
   name. The real `SKILL.md` (body, resources, and the way the skill is listed) is
   never loaded. `run_trigger_eval.py` installs the real skill under
   `.claude/skills` in a fresh sandbox project and checks it is listed.
2. **It runs in the wrong place.** It walks up from the working directory to the
   first ancestor holding a `.claude` directory. Launched from the plugin cache
   that is the home directory, so the user's whole configuration (other skills,
   MCP servers, memory) competes with the skill and the run is not reproducible.
   The sandbox here uses project settings only.
3. **It scores a miss too early.** The first tool call that is not `Skill` or
   `Read` ends the run as "not triggered". Claude often starts with `Glob` to
   look at the repository and calls the skill one step later, so those runs count
   as misses. Here a `Skill` call within the first three tool calls counts.

A fourth, smaller point: the stock script passes the description to YAML as a
block scalar, so a description that is invalid as a plain frontmatter scalar
(a colon followed by a space) still loads there. `run_trigger_eval.py` quotes the
text the same way, so check a candidate with `gh skill publish --dry-run` before
adopting it.

## Behaviour evals

`evals.json` follows the skill-creator schema. Prompts name fixture paths relative
to the skill directory. The guide's canonical URL is not reachable before the
guide is merged to `main`, so a run gives the agent a local stand-in path for it;
eval 2 withholds it to test the index fallback. Eval 5 is a debugging scenario:
a server whose verifier audience does not match its service's audience.
