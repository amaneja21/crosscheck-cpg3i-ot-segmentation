# CrossCheck

CrossCheck checks whether an OT (operational technology) network satisfies
CISA's Cross-Sector Cybersecurity Performance Goal 3.I, Network
Segmentation, straight from evidence a utility or plant already has:
observed network traffic and the policy that governs it. No new sensors
and no big compliance platform, just a direct read against the standard.

Full write-up: **[paper link goes here once it's posted]**

## What's in this repo

- **`tool/`** — CrossCheck itself, a small runnable script. Point it at
  flow and policy evidence in the schema described in the paper and it
  checks a network against three of CPG 3.I's four elements: distinct
  segments behind a boundary device, inter-segment traffic tight enough
  to contain a breach, and, where the standard calls for it, physical
  isolation of an OT enclave like a safety system behind a data diode.

- **`evaluation/`** — the hand-built test scenarios, ground truth
  labels, and the evaluation code behind the results in the paper
  (Section 5), including the comparison against a simple keyword
  matching baseline meant to represent current manual audit practice.

## Quick start

```
cd tool
python3 crosscheck.py --flows examples/scenario1_flows.json --policy examples/scenario1_policy.json
```

That runs the first of six example scenarios and prints a verdict. See
`tool/README.md` for the full input format and all six examples,
they reproduce the results table in the paper exactly.

## Status

This is an early, hand built proof of concept, not a finished product.
It currently expects flow and policy evidence already normalized into
a simple schema. It does not yet parse a real firewall's exported logs
or a real switch ACL directly, that normalization step is still manual.
`tool/README.md` covers exactly what it does and doesn't do, and the
paper's Limitations section covers what's planned next.

## Citing this work

If you reference this project, please cite the paper:

> [Author], "[Paper title]," [venue / preprint server], [year]. [link]

(Full citation details will be added here once the paper is posted.)

## License

MIT, see `LICENSE`.
