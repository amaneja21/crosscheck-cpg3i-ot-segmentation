# Evaluation dataset v1 — CPG 3.I compliance engine, Section 5.1

This is the small, hand built labeled set agreed as the starting point before
scaling to a full multi-topology generator: one vendor syntax, grounded in
the Rev D reference topology (`topology-reference.html`), covering
the water treatment facility's Purdue Level 4 through 0 layout.

## What's in here

- `topology-reference.html` — the Rev D source topology artifact
  itself (Water Treatment OT Topology), included here for context so the
  policy and traffic files below can be read against the actual diagram
  and asset table they're derived from, instead of a description of it.

- `policy/` — Cisco ASA style extended ACLs (the single vendor syntax chosen
  to start; Checkpoint and Zscaler Zero Trust Branch syntax are the planned
  next two per the three-syntax evaluation plan already agreed for the full
  dataset).
  - `baseline_host_routed.acl` — the reference policy, host routed deployment
    shape, deny by default everywhere including area to area.
  - `perimeter_ngfw_only.acl` — same topology, plain perimeter NGFW shape,
    which structurally has nothing to say about area to area traffic.
  - `case03_overbroad_interarea.acl` — baseline with one planted change (an
    Intake-to-Filtration deny widened to permit any/any), also used by case08.
- `traffic/` — one normalized evidence file per case, using the Section 4.1
  schema (source, destination, protocol, port, direction, observed_frequency,
  first_seen), plus two supporting engineering notes for the Clause 4 cases.
- `labels.json` — ground truth verdict and rationale per case, per clause.

## Case set (9 cases)

| Case | Clause exercised | Verdict |
|---|---|---|
| 01 baseline | all | compliant |
| 02 boundary missing | 1 | violation |
| 03 overbroad inter-area rule | 2 | violation |
| 04 perimeter NGFW abstention | 2 | no evidence |
| 05 diode reversal | 3 | violation |
| 06 diode compliant | 3 | compliant |
| 07a exception, genuine constraint | 4 | compliant via exception |
| 07b exception, pretextual | 4 | violation |
| 08 combined | 2 and 3 together | both violations, single pass |

This gives at least one compliant and one violating example for each of the
three deterministic clauses in Section 4.3, a matched positive/negative pair
for the judgment-requiring Clause 4 exception, and a stress case that checks
whether the engine reports every finding in one evaluation instead of
stopping at the first. That's enough for a real precision/recall/F1 read on
a small set, in the spirit of the labeled-set methodology in [6], without
committing to a large build before the prototype exists to run against it.

## Two design choices that go beyond what's explicitly in the current
## paper draft — flagging both for review before they're treated as settled

**The NO_EVIDENCE verdict class (case04).** Section 5.1 as currently written
names three planted violation types and implicitly frames every case as a
pass/fail. But Section 5.2's own collection-method-invariance framing, and
the topology reference's note that a plain perimeter NGFW "has no evidence
either way" on area-to-area traffic, both point at a real fourth outcome:
the engine correctly declining to score a clause it cannot see evidence for.
Defaulting to compliant would be silently wrong under a weak deployment,
and defaulting to violation would unfairly penalize a legitimate
architecture choice. If the prototype doesn't already plan to support this
as a distinct output, better to decide that now, before the labeled set
is built out further, since it changes what "correct" means for case04.

**The Clause 4 test cases (07a/07b).** The topology reference explicitly
deferred picking a concrete example for the "where safe and technically
feasible" exception until the labeled dataset was being built. This dataset
invents one: a hazardous-area electrical classification constraint that
genuinely prevents adding a second network device (07a), paired with a
device sharing the same segment for a budget reason that should NOT earn
the exception (07b). This is a plausible OT scenario but not one confirmed
against real customer deployment patterns the way the topology's VLAN
numbering flagged for Zero Trust Branch confirmation. Worth a sanity check
against real field examples before this becomes the paper's load-bearing
Clause 4 evidence, the same way the SIS enclave's function was flagged for
confirmation before it became load-bearing for Clause 3.

## Passive/SPAN cases and the evaluation harness

`traffic_span/` mirrors most of the inline cases (boundary, overbroad
inter-area, diode, combined) under the passive/SPAN deployment shape from
the topology reference, checked against separate core-switch ACLs in
`policy/switch_acl_baseline.acl` and `policy/switch_acl_overbroad.acl`,
not the inline appliance's policy. `traffic_span/span_case04...`
is a second, distinct route to a NO_EVIDENCE verdict: here the tap
captures area to area traffic fine, but no switch ACL export exists to
check it against, versus case04's inline scenario where the traffic
itself is the missing half. 16 cases total across both collection
methods, still small and hand built, per the "start simple" agreement.

`harness/` has two real, runnable checkers and a scorer, this isn't just
labels sitting there: `baseline_checker.py` is a naive, keyword and
static-rule matcher meant to represent current manual/semi-automated
practice, `engine_checker.py` correctly implements the deterministic
parts of Section 4.3 (real subnet-aware policy parsing, traffic cross
referenced against policy, explicit NO_EVIDENCE output instead of a
guess) plus a keyword heuristic standing in for the Section 4.4
reasoning layer on the Clause 4 exception cases specifically. Run
`python3 harness/scorer.py` from the dataset root to regenerate
`results/evaluation_report.md` and `results/predictions.json`.

Headline numbers from that run: baseline scores 0.783 F1 on violation
detection across all 16 cases, engine scores 1.000, roughly a 22 point
gap, inside the paper's own 15-25 point planning target from ref [6].
Read `results/evaluation_report.md`'s closing section before repeating
that number anywhere in the paper. The engine's 1.000 just reflects an
internally consistent implementation of an already-agreed spec on a
2-example exception set. It isn't a validated LLM reasoning layer yet,
and needs a real held out test before it's evidence of anything beyond
that.

## Suggested next step

The baseline vs engine comparison this dataset was meant to support now
has a first real run behind it. What's still missing before that number
means anything in the paper: a genuine LLM call wired into Clause 4 in
place of the keyword stand-in, and more than 2 exception examples to
judge it against, since 2 is enough to build the harness but not enough
to trust the 2/2 score.
