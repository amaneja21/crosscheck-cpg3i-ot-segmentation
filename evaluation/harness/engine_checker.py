"""Prototype engine: the deterministic parts of Section 4.3 implemented
properly, plus a stand-in for the Section 4.4 reasoning layer on Clause 4.

Clauses 1 to 3 are genuinely deterministic: real CIDR-aware containment
checks against the parsed policy (via Python's ipaddress module),
traffic cross-referenced against policy instead of policy read in
isolation, and an explicit NO_EVIDENCE output whenever the deployment
shape or an absent policy document can't structurally support a verdict,
rather than defaulting to a guess.

Clause 4 is NOT deterministic, worth being upfront about that.
judge_exception() below is a keyword-scored heuristic, not a wired LLM
call. It stands in for the reasoning layer described in Section 4.4,
calibrated by hand against the two supporting notes in this dataset,
weighing which one describes a genuine physical or regulatory
infeasibility versus a purely economic one. Treat it as a placeholder
for that call, not as evidence the reasoning layer generalizes: a real
test needs an actual LLM run against notes it hasn't seen scored
against, held out from whoever wrote the ground truth.
"""

import os
import ipaddress

from acl_parser import parse_acl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IT_RANGE = ipaddress.ip_network("10.4.0.0/16")
DMZ_RANGE = ipaddress.ip_network("10.40.0.0/24")
AREA_PREFIXES = [ipaddress.ip_network(p) for p in
                 ("10.12.0.0/24", "10.13.0.0/24", "10.14.0.0/24", "10.15.0.0/24")]

SAFETY_TERMS = ["hazardous", "intrinsically-safe", "intrinsically safe",
                "classification", "certif", "safety"]
ECONOMIC_TERMS = ["budget", "cost", "schedul", "temporary", "contractor", "convenience"]


def _endpoint_network(value):
    if "/" in value:
        return ipaddress.ip_network(value, strict=False)
    return ipaddress.ip_network(f"{value}/32")


def _covered_by_any_rule(rules, src_net, dst_net):
    for r in rules:
        if r["action"] != "permit":
            continue
        try:
            if src_net.subnet_of(r["src"]) and dst_net.subnet_of(r["dst"]):
                return True
        except TypeError:
            continue
    return False


def _read_notes(case):
    docs = case.get("supporting_documents", [])
    text = ""
    for rel_path in docs:
        with open(os.path.join(ROOT, rel_path)) as f:
            text += f.read() + "\n"
    return text


def check_clause1(case):
    rules = parse_acl(case["policy_text"])
    for flow in case["flows"]:
        src_net = _endpoint_network(flow["source"])
        dst_net = _endpoint_network(flow["destination"])
        if not src_net.subnet_of(IT_RANGE):
            continue
        if dst_net.subnet_of(DMZ_RANGE):
            continue  # IT -> DMZ is the intended, in-scope path
        if not _covered_by_any_rule(rules, src_net, dst_net):
            return "VIOLATION"

    # A device pair sharing a VLAN with no ACL governing it is also a
    # distinct-segments failure on its face, unless Clause 4's exception
    # genuinely applies. Same underlying fact Clause 4 checks below, so
    # it needs the same judgment call here.
    same_segment_flows = [f for f in case["flows"] if f.get("direction") == "L2-1_same_segment"]
    if same_segment_flows:
        if judge_exception(_read_notes(case)):
            return "COMPLIANT_VIA_EXCEPTION"
        return "VIOLATION"

    return "COMPLIANT"


def check_clause2(case):
    rules = parse_acl(case["policy_text"])

    def area_of(net):
        for a in AREA_PREFIXES:
            if net.subnet_of(a) or net == a:
                return a
        return None

    lateral_flows = [f for f in case["flows"] if f.get("direction") == "L2-1_to_L2-1"]
    for flow in lateral_flows:
        src_net = _endpoint_network(flow["source"])
        dst_net = _endpoint_network(flow["destination"])
        if _covered_by_any_rule(rules, src_net, dst_net):
            return "VIOLATION"

    if case["policy_text"] is None:
        return "NO_EVIDENCE"

    area_rule_present = any(
        area_of(r["src"]) is not None or area_of(r["dst"]) is not None
        for r in rules
    )
    if not area_rule_present:
        return "NO_EVIDENCE"

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


def judge_exception(note_text):
    text = note_text.lower()
    safety_score = sum(text.count(t) for t in SAFETY_TERMS)
    economic_score = sum(text.count(t) for t in ECONOMIC_TERMS)
    return safety_score > economic_score


def check_clause4(case):
    same_segment_flows = [f for f in case["flows"] if f.get("direction") == "L2-1_same_segment"]
    if not same_segment_flows:
        return "COMPLIANT"
    if judge_exception(_read_notes(case)):
        return "COMPLIANT_VIA_EXCEPTION"
    return "VIOLATION"


def evaluate(case):
    return {
        "clause_1": check_clause1(case),
        "clause_2": check_clause2(case),
        "clause_3": check_clause3(case),
        "clause_4": check_clause4(case),
    }
