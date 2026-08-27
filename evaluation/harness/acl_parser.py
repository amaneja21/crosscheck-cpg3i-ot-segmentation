"""Minimal parser for the two ACL dialects used in this dataset: Cisco ASA
extended access-list lines (the inline appliance) and Cisco IOS extended
named ACL lines (the core switch). Both checkers use this to turn raw text
into (action, proto, src_network, dst_network, dst_port) rules -- parsing
syntax is not itself the compliance question either script is trying to
answer, so sharing it doesn't blur the two checkers' actual logic."""

import ipaddress


def _mask_to_network(ip, mask_token):
    octets = [int(x) for x in mask_token.split(".")]
    if octets[0] >= 128:
        netmask = mask_token
    else:
        netmask = ".".join(str(255 - o) for o in octets)
    return ipaddress.ip_network(f"{ip}/{netmask}", strict=False)


def _parse_endpoint(toks, idx):
    if toks[idx] == "host":
        net = ipaddress.ip_network(f"{toks[idx + 1]}/32")
        return net, idx + 2
    if toks[idx] == "any":
        return ipaddress.ip_network("0.0.0.0/0"), idx + 1
    net = _mask_to_network(toks[idx], toks[idx + 1])
    return net, idx + 2


def parse_acl(text):
    if not text:
        return []
    rules = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("!") or line.lower().startswith("remark"):
            continue
        if line.lower().startswith("ip access-list"):
            continue
        toks = line.split()
        if toks[0] == "access-list":
            toks = toks[3:]  # drop "access-list NAME extended"
        if not toks or toks[0] not in ("permit", "deny"):
            continue
        action, proto = toks[0], toks[1]
        idx = 2
        src, idx = _parse_endpoint(toks, idx)
        src_port = None
        if idx < len(toks) and toks[idx] == "eq":
            src_port = toks[idx + 1]
            idx += 2
        dst, idx = _parse_endpoint(toks, idx)
        dst_port = None
        if idx < len(toks) and toks[idx] == "eq":
            dst_port = toks[idx + 1]
            idx += 2
        rules.append({
            "action": action, "proto": proto,
            "src": src, "dst": dst,
            "src_port": src_port, "dst_port": dst_port,
        })
    return rules
