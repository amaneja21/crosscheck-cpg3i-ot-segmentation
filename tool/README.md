# CrossCheck demo tool

A small, real, runnable version of the tool described in the paper (see
Section 4, link at the top of the repo's main README). It implements
the three deterministic checks against CPG 3.I's Network Segmentation
goal: boundary, containment, and physical isolation.

This is the simple version on purpose. It reads flow and policy evidence
that's already in the canonical group-to-group schema from Table 1. It
does not parse a real firewall export, a Palo Alto or Cisco config, or a
Zscaler Zero Trust Branch policy directly. Getting a real export into
this schema is still a manual step, Section 6 lists that as scoped out
for now. What this tool actually proves is smaller than it might sound:
once evidence is in that shape, the checks themselves are simple and
deterministic.

## What you need

Two files, `flows` and `policy`, each either `.json` (a list of objects)
or `.csv` (a header row plus rows).

**flows** — one record per observed flow:

```json
{
  "source_group": "Intake Group",
  "destination_group": "Filtration Group",
  "protocol": "TCP",
  "port": 502,
  "frequency": "continuous",
  "first_seen": "2026-01-04"
}
```

`protocol`, `port`, `frequency`, and `first_seen` are carried through but
not required by the checks themselves, they're there because that's what
a firewall or switch actually logs by default. Only `source_group` and
`destination_group` matter for the verdicts.

**policy** — one record per rule, in the same shape as Table 1:

```json
{
  "source_group": "Intake Group",
  "destination_group": "Filtration Group",
  "action": "ALLOW"
}
```

`action` is `ALLOW` or `DENY`. `source_group` or `destination_group` can
be `"ANY"` to represent a wildcard rule, that's what the containment
check flags as too broad. A record can also carry
`"physical_control": "diode"` to mark a pair as physically, one way,
isolated, that's what the physical isolation check looks for.

**check-pairs** (optional) — group pairs you want an honest answer on
even if there's no data either way:

```json
{ "source_group": "SCADA Group", "destination_group": "Distribution Group" }
```

Without this, the tool only reports on pairs that show up in flows or
policy. A pair with genuinely nothing in either file is exactly the
insufficient-evidence case, and the only way to see that verdict is to
ask about the pair directly.

## Running it

```
python3 crosscheck.py --flows flows.json --policy policy.json [--check-pairs pairs.json] [--out results.json]
```

Prints one line per pair checked, its verdict, and why, and writes the
same thing as JSON to `--out` (default `crosscheck_results.json`). Exit
code is 1 if any violation was found, 0 otherwise, same convention
`grep` uses. Easy to wire into a script, and a nonzero exit here means
violations, it doesn't mean the command broke.

Verdicts: `COMPLIANT`, `BOUNDARY_VIOLATION`, `CONTAINMENT_VIOLATION`,
`PHYSICAL_ISOLATION_VIOLATION`, `INSUFFICIENT_EVIDENCE`.

## Try it against the six scenarios from the paper

`examples/` has flows and policy files for each of the six scenarios in
Table 2. Running each one reproduces that table's verdicts exactly:

```
python3 crosscheck.py --flows examples/scenario1_flows.json --policy examples/scenario1_policy.json
python3 crosscheck.py --flows examples/scenario2_flows.json --policy examples/scenario2_policy.json
python3 crosscheck.py --flows examples/scenario3_flows.json --policy examples/scenario3_policy.json
python3 crosscheck.py --flows examples/scenario4_flows.json --policy examples/scenario4_policy.json --check-pairs examples/scenario4_pairs.json
python3 crosscheck.py --flows examples/scenario5_flows.json --policy examples/scenario5_policy.json
python3 crosscheck.py --flows examples/scenario6_flows.json --policy examples/scenario6_policy.json
```

| Scenario | Verdict this tool returns |
|---|---|
| 1: compliant network | COMPLIANT |
| 2: undocumented path into a segment | BOUNDARY_VIOLATION |
| 3: overly broad rule between two segments | CONTAINMENT_VIOLATION |
| 4: no documented policy for the pair | INSUFFICIENT_EVIDENCE |
| 5: reverse traffic on an isolated enclave | PHYSICAL_ISOLATION_VIOLATION |
| 6: genuine one way traffic on that enclave | COMPLIANT |

## Using it on your own data

Export your flow evidence (inline: the NGFW's own traffic log; passive or
SPAN: the tap's captured traffic) and your policy (inline: the device's
rule groups; passive or SPAN: the switch and router ACLs) into the two
schemas above, by hand for now, and point the tool at those files. If
your evidence covers pairs of interest that never show up as either a
flow or a rule, list them in a check-pairs file so the tool tells you
that honestly instead of staying silent about them.

## What this is not

It's not the ../evaluation harness (that one parses real ASA and IOS
style ACL syntax, this one deliberately doesn't). It's not wired to any
real firewall or SPAN feed. And the wildcard/diode logic here is a
direct implementation of Section 4's description. It hasn't been
checked against a live deployment yet, that's still the honest next
step Section 5 and 6 both point at.
