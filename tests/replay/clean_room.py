"""The clean-room Tool Broker: answers the executor's envelope requests the way a customer with no context would.

Empty lists, no baselines, no change windows, no precedents, no reputation hits. Telemetry in the alert itself (roles,
the raw vendor values the translations read, the endpoint API's matched alerts) is used as-is. A test case may supply
what the clean room cannot know: context answers, coverage reports, broker answers per question (overrides), recorded
closes (for C-04), fallback-source answers (not_checked), and a synthetic customer's verifications.

This is a test harness, not bank content: it names products and translation tables. It implements the answerer interface
of engine/executor.py: ask(request) -> [{"at": ..., "answer": {...}}]. It answers at the request's sent_at, which is the
fixed time the caller passed to the executor (tools/replay.py NOW); the clean room has no clock of its own.
"""
import ipaddress
import itertools
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for p in (ROOT, os.path.join(ROOT, "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402

_IDS = itertools.count(1)
ENTITY_ROLE = {"process": "process.guid", "parent_process": "process.parent_guid", "module": "process.guid", "file": "file.path",
               "recipient_hosts": "email.recipient"}


def ref_value(ref, n):
    """Value of a role:/derived:/alert: reference, or of the role an entity: reference needs (None if missing)."""
    kind, _, name = ref.partition(":")
    if kind == "entity":
        return n.get(ENTITY_ROLE[name])
    return E.ref_value(ref, n)


def entity_of(n):
    """The grouping entity the normalizer sets on the alert (alert:entity): the host, else the user, else the recipient."""
    return n.get("host.name") or n.get("user.name") or n.get("email.recipient")


def _minutes(t):
    """Minutes since the epoch for the time formats the datasets use; 0 when a time is missing or unreadable (every such
    alert then counts as simultaneous, which can only make an entity hotter)."""
    from datetime import datetime
    t = str(t or "").strip()
    for parse in (lambda x: datetime.fromisoformat(x.replace("Z", "+00:00")), lambda x: datetime.strptime(x[:19], "%m/%d/%Y %I:%M:%S"),
                  lambda x: datetime.strptime(x[:19], "%m/%d/%Y %H:%M:%S"), lambda x: datetime.fromtimestamp(float(x))):
        try:
            return parse(t).timestamp() / 60
        except (ValueError, OverflowError, OSError):
            pass
    return 0.0


class CleanRoom:
    """One clean-room broker for one replay or one test case. case keys (all optional): alerts (this detection's earlier
    alerts, for alert.history), timeline (every alert seen on the entities, for C-02 and C-03), conns (connection records),
    context ({C-xx: value}; None = unknown), coverage, overrides ({question: value}), closures, not_checked ([question]),
    routine ([(entity, detection)]), customer, today, vuln_unknown (a Counter the vulnerability lookups report into)."""

    def __init__(self, b, **case):
        self.b, self.case, self.alerts, self.seq = b, case, {}, 0

    def register(self, n):
        """Give a normalized alert its alert_id and grouping entity, as the normalizer does, and remember it."""
        n.setdefault("alert_id", f"cr:{next(_IDS)}")
        n["entity"] = entity_of(n)
        self.alerts[n["alert_id"]] = n
        return n

    def ask(self, request):
        n = self.alerts[request["alert_id"]]
        self._trust, self._prov = "checked", None
        qid = request["question_id"]
        if qid in self.b["context_questions"]:
            value = self.context(qid, n, request.get("inputs") or {})
        else:
            q = self.b["questions"][qid]
            if set((q.get("needs") or {}).get("coverage") or []) - set(self.case.get("coverage") or []):
                value = None   # no coverage report: the question is no_capability, its step follows on_unknown
            else:
                inputs = dict(q["capability"].get("inputs", {}))
                inputs.update(request.get("bind") or {})
                value = self.measure(q, inputs, n)
                if qid in (self.case.get("not_checked") or []) and value is not None:
                    self._trust, self._prov = "not_checked", self._prov or "fallback source"   # a case's fallback-source answer
        self.seq += 1
        msg = {"request_id": request["request_id"], "measurement_id": f"m-{self.seq}",
               "answer": value if value is not None else "unknown", "status": "answered" if value is not None else "unknown",
               "trust": self._trust, "provenance": {"source": "clean_room", "ref": self._prov}}
        for k in ("run_id", "entity_window_id"):
            if k in request:
                msg[k] = request[k]
        return [{"at": request["sent_at"], "answer": msg}]

    # ---------- context questions ----------
    def context(self, cid, n, inputs):
        """C-01, C-06, C-08 and the others from the case's context (C-01 defaults to no open escalation); C-02 and C-03 from
        the alerts on the same entity seen so far; C-04 from the recorded closes of the fingerprint, by the human-evidence
        definition. Measured fresh on every request: a new alert on the entity is always counted (S1)."""
        b, case = self.b, self.case
        given = dict({"C-01": False}, **(case.get("context") or {}))
        if cid in given:
            return given[cid]
        if cid not in ("C-02", "C-03", "C-04"):
            return None
        if cid == "C-04":
            fp = n.get("fingerprint")
            return E.human_evidence(b, [c for c in case.get("closures") or [] if c.get("fingerprint", fp) == fp])
        seen = case.get("timeline") if case.get("timeline") is not None else (case.get("alerts") or [])[:n.get("_idx", 0) + 1]
        now = _minutes(n.get("event.time"))
        window, look = float(inputs.get("window", 0)), float(inputs["lookback_hours"]) * 60
        mine = [x for x in seen if entity_of(x) == entity_of(n) and now - look <= _minutes(x.get("event.time")) <= now]
        if cid == "C-02":
            routine = {tuple(r) for r in case.get("routine") or []}
            counted = [x for x in mine if (entity_of(x), x.get("_detection")) not in routine or x.get("severity") in ("high", "critical")]
            in_window = [x for x in counted if now - window <= _minutes(x.get("event.time"))]
            c02 = {"alerts": len(in_window), "distinct_detections": len({x.get("_detection") for x in in_window})}
            top = {}
            for x in counted:
                if E.severity_rank(b, x.get("severity")) is not None:
                    top[x.get("_detection")] = max(top.get(x.get("_detection"), x["severity"]), x["severity"], key=lambda s: E.severity_rank(b, s))
            for level in b["severity"]["scale"]:
                c02[f"day_detections_{level}"] = sum(1 for v in top.values() if v == level)
            return c02
        if cid == "C-03":
            others = [x.get("severity") for x in mine if x is not n and E.severity_rank(b, x.get("severity")) is not None]
            return max(others, key=lambda s: E.severity_rank(b, s)) if others else "none"

    # ---------- triage questions ----------
    def measure(self, q, inputs, n):
        """The broker's typed answer for one question on one alert, or None for status unknown."""
        b, case = self.b, self.case
        cap = q["capability"]["name"]
        if cap == "email.no_interaction" and n.get("file.sha256") and "attachment_open_telemetry" not in (case.get("coverage") or []):
            return None   # B2: the message carried an attachment and no host records attachment opens: missing clicks are not evidence
        if cap == "email.no_interaction" and n.get("email.url") and "link_click_telemetry" not in (case.get("coverage") or []):
            return None   # #29: the message carried a link and link clicks are not recorded for the recipient: missing clicks are not evidence
        if q["id"] in (case.get("overrides") or {}):
            return case["overrides"][q["id"]]   # a test case supplies a broker answer the clean room cannot give
        optional = set(q["capability"].get("optional_inputs") or [])
        for kind, name in B.walk_refs({k: v for k, v in inputs.items() if k not in optional}):
            if kind != "bind" and ref_value(f"{kind}:{name}", n) in (None, ""):
                return None
        if cap == "alert.class":
            cls = inputs["class"]
            tables = [t for t in n.get("_tables", []) if cls in (b["value_tables"].get(t, {}).get("classes") or {})]
            if tables:
                values = n.get("_raw") or {}
            else:
                reads = [inputs["of"].split(":", 1)[1]] if inputs.get("of") else b["capabilities"]["alert_classes"][cls]["reads"]
                values = {r: n.get(r) for r in reads}
                if all(v in (None, "") for v in values.values()):
                    return None
                # further role inputs (for example the email delivery stage) are read by the translation too
                values.update({str(v).split(":", 1)[1]: n.get(str(v).split(":", 1)[1]) for k, v in inputs.items()
                               if k not in ("class", "of") and str(v).startswith("role:")})
            v, self._trust, self._prov = B.classify_effective(b, cls, values, tables, ctx=case, question=q["id"])
            return v
        if cap == "endpoint.run_status":
            # The endpoint API is authoritative (_api: the vendor alerts it matched); without it the SIEM's copy of the alert
            # is the fallback (_raw read through the product's siem_copy table, else the generic one).
            copy = {"raw": n.get("_raw") or {"value": n.get("reporting_control.action_raw")}, "tables": n.get("_tables") or []}
            v, self._trust, self._prov = B.run_status(b, n.get("_api"), copy, ctx=case, sha256=n.get("file.sha256"))
            return v
        if cap == "list.lookup" and (b["facts"].get(inputs.get("list")) or {}).get("default_entries"):
            # A context list that starts from default entries (CF-0031 internal networks: the private ranges) holds them in the clean room.
            try:
                ip = ipaddress.ip_address(str(ref_value(inputs["entity"], n)))
            except ValueError:
                return None
            return any(ip in ipaddress.ip_network(c) for c in b["facts"][inputs["list"]]["default_entries"])
        if cap == "alert.measure":
            return float(ref_value(inputs["of"], n))
        if cap == "traffic.denied_only":
            conns = [x for x in case.get("conns") or [] if x.get("src.ip") == n.get("src.ip")]
            return None if not conns else all(x.get("reporting_control.action") == "blocked" for x in conns)
        if cap == "alert.history":
            key = inputs["key"]
            earlier = [x for x in (case.get("alerts") or [])[:n["_idx"]] if ref_value(key, x) == ref_value(key, n)]
            if inputs.get("distinct"):
                return len({ref_value(inputs["distinct"], x) for x in earlier})
            return len(earlier)
        if cap == "vuln.not_applicable":
            case["vuln_unknown"][("no_cve_mapping" if not re.search(r"CVE-\d{4}-\d+", str(n.get("reporting_control.signature")), re.I) else "no_data")] += 1
            return None
        if cap in ("entity.baseline", "org.prevalence", "email.message_status", "email.no_interaction", "email.auth", "file.signer"):
            return None
        return False   # list.lookup (CF-0031 internal networks included), identity.groups, change.window, scan.job_active, *.reputation: empty in a clean room
