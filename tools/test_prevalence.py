#!/usr/bin/env python3
"""Prove the org.prevalence statistic keeps the old rule with no threshold at the broker.

The broker returns the k-th lowest weekly distinct-host count over of_weeks weeks, k = of_weeks - min_weeks + 1.
The Triage agent then checks it against N (org_prevalence_min_hosts). This test checks, over every case with
4 weeks (each week 0..11 hosts, so quiet weeks with 0 hosts are included) and N from 1 to 10, for min_weeks 1..4,
that "k-th lowest >= N" equals "at least min_weeks of the of_weeks weeks have >= N hosts".

Usage: tools/test_prevalence.py   exit 1 on any mismatch
"""
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402


def main():
    of_weeks, cases, bad = 4, 0, []
    for min_weeks in range(1, of_weeks + 1):
        for weeks in itertools.product(range(12), repeat=of_weeks):
            stat = B.kth_lowest_weekly_hosts(list(weeks), of_weeks, min_weeks)
            for n in range(1, 11):
                cases += 1
                old_rule = sum(1 for w in weeks if w >= n) >= min_weeks
                if (stat >= n) != old_rule:
                    bad.append((weeks, min_weeks, n, stat))
    quiet = [w for w in itertools.product(range(12), repeat=of_weeks) if 0 in w]
    print(f"org.prevalence statistic: {cases} cases (4 weeks of 0..11 hosts, {len(quiet)} weekly patterns with a quiet week, "
          f"N 1..10, min_weeks 1..4): {len(bad)} mismatches -> {'PASS' if not bad else 'FAIL'}")
    for x in bad[:10]:
        print("  mismatch", x)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
