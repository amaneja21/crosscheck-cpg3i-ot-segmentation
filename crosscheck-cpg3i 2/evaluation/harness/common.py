"""Shared case loading for both checkers. Reading files off disk has
nothing to do with compliance logic, so it lives here once. The actual
clause logic stays split between baseline_checker.py and
engine_checker.py, each a separate, independent implementation."""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_policy(policy_file):
    if not policy_file:
        return None
    path = os.path.join(ROOT, policy_file)
    with open(path) as f:
        return f.read()


def load_cases():
    cases = []
    for subdir in ("traffic", "traffic_span"):
        d = os.path.join(ROOT, subdir)
        for fname in sorted(os.listdir(d)):
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(d, fname)) as f:
                data = json.load(f)
            data["policy_text"] = _read_policy(data.get("policy_file"))
            cases.append(data)
    return cases


def load_labels():
    with open(os.path.join(ROOT, "labels.json")) as f:
        return json.load(f)
