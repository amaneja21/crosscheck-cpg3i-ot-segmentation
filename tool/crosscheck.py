#!/usr/bin/env python3
"""CrossCheck demo tool.

Runs the three checks from Section 4 of the paper (boundary, containment,
physical isolation) against the group-to-group schema from Table 1. This
is the simple version on purpose: it expects flow and policy evidence
that's already in that schema. It won't parse a real firewall's ACL
syntax or a raw traffic log for you, turning an actual export into this
shape is still a manual step for now, see README.md.

Inputs:

  --flows FILE      Observed traffic. Fields: source_group,
                    destination_group, protocol, port, frequency,
                    first_seen. Only the first two actually drive a
                    verdict, the rest just gets carried through.

  --policy FILE     Policy in the Table 1 shape: source_group,
                    destination_group, action (ALLOW/DENY). Add
                    physical_control: "diode" on a record to mark it as
                    a one way hardware boundary, see
                    check_physical_isolation below.

  --check-pairs FILE   (optional) Pairs you want an answer on even with
                        no data either way. Skip this and the tool just
                        won't mention a pair nobody asked about, which
                        looks like "fine" when it's really "no idea."

.json (a list of objects) or .csv (header row plus rows) both work for
all three inputs.

Writes one verdict per pair to stdout, and the same thing as JSON to
--out (default crosscheck_results.json).
"""

import argparse
import csv
import json
import os
import sys

VALID_ACTIONS = {"ALLOW", "DENY"}


def load_records(path):
    if path is None:
        return []
    ext = os.path.splitext(path)[1].lower()
    with open(path) as f:
        if ext == ".json":
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError(f"{path}: expected a JSON list of records")
            return data
        if ext == ".csv":
            return list(csv.DictReader(f))
    raise ValueError(f"{path}: unsupported file type, use .json or .csv")


def pair_key(record):
    return (record["source_group"], record["destination_group"])


def index_by_pair(records):
    """Last record wins for a given pair, same as a firewall rule base
    evaluated top to bottom. Two records naming the exact same pair is a
    policy authoring mistake somewhere upstream, this tool won't try to
    average the two out."""
    index = {}
    for r in records:
        index[pair_key(r)] = r
    return index


def find_covering_policy(src, dst, policy_index, wildcard_records):
    """Exact match wins. Otherwise fall back to a wildcard record, ANY as
    source, destination, or both, in the same order a firewall checks
    its specific rules before falling through to the catch-all."""
    if (src, dst) in policy_index:
        return policy_index[(src, dst)]
    for r in wildcard_records:
        r_src, r_dst = r.get("source_group"), r.get("destination_group")
        if r_src in (src, "ANY") and r_dst in (dst, "ANY") and (r_src == "ANY" or r_dst == "ANY"):
            return r
    return None


def evaluate_pair(src, dst, flow_observed, policy_record):
    """Covers Clause 1 (boundary) and Clause 2 (containment) together,
    they read the same two inputs: whether a policy record exists for
    this pair, and if so, whether it's scoped tight or a wildcard."""
    if policy_record is None:
        if flow_observed:
            return ("BOUNDARY_VIOLATION",
                    "traffic was observed on this path and no policy record covers it")
        return ("INSUFFICIENT_EVIDENCE",
                "neither traffic nor a policy record exists for this pair")

    action = str(policy_record.get("action", "")).upper()
    if action not in VALID_ACTIONS:
        return ("INSUFFICIENT_EVIDENCE",
                f"policy record for this pair has no recognizable action ({policy_record.get('action')!r})")

    wildcard = policy_record.get("source_group") == "ANY" or policy_record.get("destination_group") == "ANY"

    if action == "ALLOW":
        if wildcard:
            return ("CONTAINMENT_VIOLATION",
                    "the covering rule allows via a wildcard group, broader than a rule meant to contain a breach should be")
        return ("COMPLIANT",
                "traffic is covered by a rule scoped to exactly this pair")

    # action == DENY
    if flow_observed:
        return ("CONTAINMENT_VIOLATION",
                "policy denies this path but traffic was observed anyway")
    return ("COMPLIANT",
            "policy denies this path and no traffic was observed crossing it")


def check_physical_isolation(flows, policy):
    """Clause 3. A physical_control: diode record names the one
    direction the hardware is supposed to allow. If flow evidence shows
    the reverse direction, no policy document fixes that: either the
    hardware isn't doing what it's documented to do, or there's no
    actual diode."""
    results = []
    for rec in policy:
        if str(rec.get("physical_control", "")).lower() != "diode":
            continue
        forward_src, forward_dst = rec["source_group"], rec["destination_group"]
        reverse_seen = any(
            f["source_group"] == forward_dst and f["destination_group"] == forward_src
            for f in flows
        )
        if reverse_seen:
            results.append({
                "source_group": forward_dst,
                "destination_group": forward_src,
                "verdict": "PHYSICAL_ISOLATION_VIOLATION",
                "reason": (f"a one way hardware boundary is documented from {forward_src} "
                           f"to {forward_dst}, but traffic was observed flowing the reverse direction"),
            })
        else:
            results.append({
                "source_group": forward_src,
                "destination_group": forward_dst,
                "verdict": "COMPLIANT",
                "reason": (f"only the documented forward direction ({forward_src} to "
                           f"{forward_dst}) was observed; no reverse traffic seen"),
            })
    return results


def run(flows, policy, check_pairs):
    specific_policy = [r for r in policy
                        if r.get("source_group") != "ANY" and r.get("destination_group") != "ANY"]
    wildcard_policy = [r for r in policy
                        if r.get("source_group") == "ANY" or r.get("destination_group") == "ANY"]
    policy_index = index_by_pair(specific_policy)

    diode_pairs = {
        (r["source_group"], r["destination_group"])
        for r in policy if str(r.get("physical_control", "")).lower() == "diode"
    }
    # match the reverse direction too, that's where a violation would
    # actually turn up in the flow evidence
    diode_pairs |= {(b, a) for (a, b) in diode_pairs}

    flow_pairs = {pair_key(f) for f in flows}
    policy_pairs = set(policy_index.keys())  # specific pairs only, a wildcard isn't a pair by itself
    asked_pairs = {(r["source_group"], r["destination_group"]) for r in check_pairs}
    all_pairs = flow_pairs | policy_pairs | asked_pairs

    results = []
    for (src, dst) in sorted(all_pairs):
        if (src, dst) in diode_pairs:
            continue  # handled by check_physical_isolation below
        verdict, reason = evaluate_pair(
            src, dst,
            flow_observed=(src, dst) in flow_pairs,
            policy_record=find_covering_policy(src, dst, policy_index, wildcard_policy),
        )
        results.append({
            "source_group": src, "destination_group": dst,
            "verdict": verdict, "reason": reason,
        })

    results.extend(check_physical_isolation(flows, policy))
    return results


def main():
    parser = argparse.ArgumentParser(description="CrossCheck demo: CPG 3.I checks against flow + policy evidence")
    parser.add_argument("--flows", required=True, help="flow evidence file (.json or .csv)")
    parser.add_argument("--policy", required=True, help="policy file in the Table 1 schema (.json or .csv)")
    parser.add_argument("--check-pairs", default=None, help="optional: group pairs to get a verdict on even with no data")
    parser.add_argument("--out", default="crosscheck_results.json", help="where to write the JSON results")
    args = parser.parse_args()

    flows = load_records(args.flows)
    policy = load_records(args.policy)
    check_pairs = load_records(args.check_pairs) if args.check_pairs else []

    results = run(flows, policy, check_pairs)

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)

    width = max((len(f"{r['source_group']} -> {r['destination_group']}") for r in results), default=20)
    for r in results:
        pair = f"{r['source_group']} -> {r['destination_group']}"
        print(f"{pair.ljust(width)}  {r['verdict']:<28} {r['reason']}")

    violations = [r for r in results if r["verdict"].endswith("VIOLATION")]
    print(f"\n{len(results)} pair(s) checked, {len(violations)} violation(s), "
          f"results written to {args.out}")
    if violations:
        sys.exit(1)


if __name__ == "__main__":
    main()
