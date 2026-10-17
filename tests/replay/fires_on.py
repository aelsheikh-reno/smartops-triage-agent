"""When a replayed event would fire a detection's source rule: declarative conditions in tests/replay/fires_on/<D-ID>.yaml.

A condition is {field, op, value} on the harness's normalised event (tests/replay/datasets.py), or a combination
{all: [...]}, {any: [...]}, {not: condition}. Ops (string comparisons ignore case; a missing field is ""):
  in, not_in     the field equals one of the values / none of them
  matches        the regular expression is found in the field
  endswith       the field ends with the value
  gte            the field, as a number, is at least the value
  cidr           the field, as an IP address, is inside one of the networks
  bitmask_any    the field, as a hexadecimal number, has any of the bits in the values
  lookup         the field is in a column of a lookup CSV that ships with the pinned security_content
                 (value: {csv, column, where: {column: value}, basename: true to compare file names only})
A rule that cannot be expressed this way goes in tests/replay/fires_on_python.py, one function per D-ID, with its reason.
This is a test harness, not bank content.
"""
import csv
import glob
import ipaddress
import os
import re

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_LOOKUPS = {}


def base(p):
    return (p or "").replace("/", "\\").split("\\")[-1].lower()


def _lookup(lookups_dir, spec):
    key = (spec["csv"], spec["column"], repr(sorted((spec.get("where") or {}).items())), bool(spec.get("basename")))
    if key not in _LOOKUPS:
        where = {k: str(v).lower() for k, v in (spec.get("where") or {}).items()}
        with open(os.path.join(lookups_dir, spec["csv"]), newline="") as fh:
            vals = {r[spec["column"]].lower() for r in csv.DictReader(fh)
                    if r.get(spec["column"]) and all((r.get(k) or "").lower() == v for k, v in where.items())}
        _LOOKUPS[key] = {x.split("\\")[-1] for x in vals} if spec.get("basename") else vals
    return _LOOKUPS[key]


def holds(cond, n, lookups_dir):
    if "all" in cond:
        return all(holds(c, n, lookups_dir) for c in cond["all"])
    if "any" in cond:
        return any(holds(c, n, lookups_dir) for c in cond["any"])
    if "not" in cond:
        return not holds(cond["not"], n, lookups_dir)
    raw, op, want = n.get(cond["field"]), cond["op"], cond["value"]
    s = "" if raw is None else str(raw)
    if op == "in":
        return s.lower() in {str(v).lower() for v in want}
    if op == "not_in":
        return s.lower() not in {str(v).lower() for v in want}
    if op == "matches":
        return re.search(want, s, re.I) is not None
    if op == "endswith":
        return s.lower().endswith(str(want).lower())
    if op == "gte":
        try:
            return float(s) >= float(want)
        except ValueError:
            return False
    if op == "cidr":
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return False
        return any(ip in ipaddress.ip_network(c) for c in want)
    if op == "bitmask_any":
        try:
            bits = int(s or "0", 16)
        except ValueError:
            return False
        return any(bits & int(m) for m in want)
    if op == "lookup":
        return (base(s) if want.get("basename") else s.lower()) in _lookup(lookups_dir, want)
    raise ValueError(f"unknown op {op}")


def load():
    """{D-ID: predicate(event) -> bool} from the YAML files, plus the Python-only exceptions."""
    from tests.replay import fires_on_python
    rules = {}
    for path in sorted(glob.glob(os.path.join(HERE, "fires_on", "D-*.yaml"))):
        doc = yaml.safe_load(open(path))
        rules[doc["detection"]] = doc
    for did in fires_on_python.RULES:
        if did in rules:
            raise ValueError(f"{did} has both a YAML and a Python fires_on rule")
        rules[did] = {"detection": did, "python": fires_on_python.RULES[did]}
    return rules


def predicate(rule, lookups_dir):
    if "python" in rule:
        return rule["python"]["fires"]
    return lambda n: holds(rule["fires_when"], n, lookups_dir)
