"""Naive baseline: keyword and static-rule matching, standing in for
current manual/semi-automated audit practice (paper Section 5.1). Each
weakness below was picked on purpose, this isn't a strawman:

  Clause 1 (boundary): checks whether the policy TEXT has a final "deny
  ip any any" line, full stop. Never touches the actual traffic, so it
  can't catch a live bypass the policy document never mentions. That's
  the manual-audit failure mode Section 1 describes, comparing rules
  against rules instead of against what's actually on the wire.

  Clause 2 (containment): scans the policy text for an unrestricted
  "permit ip" between two different area subnets. Catches an obviously
  overbroad rule fine, but has no concept of "I don't have enough
  evidence." No area-to-area entries at all, or no policy provided, and
  it just defaults to compliant.

  Clause 3 (diode): checks the direction values on the diode-tagged
  pair. It gets this one right, the paper's own point is that this
  particular check reduces to a direction field, simple enough that
  even a naive tool checking it directly should get it.

  Clause 4 (exception): no judgment at all. Any device pair sharing a
  segment with no L3 boundary gets flagged a violation, whether or not
  there's a real safety or feasibility reason behind it.
"""

from acl_parser import parse_acl


def check_clause1(case):
    text = case["policy_text"] or ""
    return "VIOLATION" if "deny ip any any" not in text else "COMPLIANT"


def check_clause2(case):
    rules = parse_acl(case["policy_text"])
    area_prefixes = {"10.12.0.0/24", "10.13.0.0/24", "10.14.0.0/24", "10.15.0.0/24"}
    for r in rules:
        if r["action"] != "permit" or r["proto"] != "ip":
            continue
        src_str, dst_str = str(r["src"]), str(r["dst"])
        if src_str in area_prefixes and dst_str in area_prefixes and src_str != dst_str:
            return "VIOLATION"
    return "COMPLIANT"


def check_clause3(case):
    pairs = {}
    for flow in case["flows"]:
        direction = flow.get("direction", "")
        if "diode" not in direction:
            continue
        key = frozenset((flow["source"], flow["destination"]))
        pairs.setdefault(key, set()).add(direction)
    for directions in pairs.values():
        if len(directions) > 1:
            return "VIOLATION"
    return "COMPLIANT"


def check_clause4(case):
    for flow in case["flows"]:
        if flow.get("direction") == "L2-1_same_segment":
            return "VIOLATION"
    return "COMPLIANT"


def evaluate(case):
    return {
        "clause_1": check_clause1(case),
        "clause_2": check_clause2(case),
        "clause_3": check_clause3(case),
        "clause_4": check_clause4(case),
    }
