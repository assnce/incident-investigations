#!/usr/bin/env python3
"""Rebuild synthetic case findings and timelines using only the standard library."""
import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def parse_time(text):
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.utcoffset() is None: raise ValueError("timezone required")
    return value.astimezone(timezone.utc)


def validate(events):
    ids = set()
    for event in events:
        if not isinstance(event.get("event_id"), str) or not event["event_id"]:
            raise ValueError("event_id required")
        if event["event_id"] in ids: raise ValueError("duplicate event_id")
        ids.add(event["event_id"])
        parse_time(event["timestamp"])
    return sorted(events, key=lambda e: parse_time(e["timestamp"]))


def authentication_findings(events):
    ordered = validate(events)
    results = []
    for index, event in enumerate(ordered):
        if event["outcome"] != "success": continue
        previous = []
        for candidate in ordered[:index]:
            if any(candidate[k] != event[k] for k in ("source_ip", "username", "host")): continue
            delta = (parse_time(event["timestamp"])-parse_time(candidate["timestamp"])).total_seconds()
            if delta > 600: continue
            if candidate["outcome"] == "success": previous.clear()
            elif candidate["outcome"] == "failure": previous.append(candidate)
        if len(previous) >= 5:
            results.append({"finding":"success_after_failures", "event_ids":[x["event_id"] for x in previous]+[event["event_id"]],
                            "source_ip":event["source_ip"], "username":event["username"], "host":event["host"],
                            "failed_attempts":len(previous), "assessment":"suspicious; compromise not established"})
    return results


def windows_findings(events):
    ordered = validate(events)
    results = []
    for logon in ordered:
        if logon.get("EventID") != 4624 or not logon.get("TargetLogonId"): continue
        session = [e for e in ordered if e.get("host") == logon["host"]
                   and e.get("SubjectLogonId") == logon["TargetLogonId"]
                   and 0 <= (parse_time(e["timestamp"])-parse_time(logon["timestamp"])).total_seconds() <= 1200]
        for account in session:
            if account.get("EventID") != 4720 or not account.get("TargetSid"): continue
            memberships = [e for e in session if e.get("EventID") == 4732
                           and e.get("TargetSid") == "S-1-5-32-544"
                           and e.get("MemberSid") == account["TargetSid"]
                           and parse_time(e["timestamp"]) >= parse_time(account["timestamp"])]
            for membership in memberships:
                services = [e for e in session if e.get("EventID") == 4697
                            and any(p in e.get("ServiceFileName", "").casefold() for p in ("\\users\\", "\\temp\\"))
                            and parse_time(e["timestamp"]) >= parse_time(membership["timestamp"])]
                for service in services:
                    clears = [e for e in session if e.get("EventID") == 1102 and parse_time(e["timestamp"]) >= parse_time(service["timestamp"])]
                    for clear in clears:
                        results.append({"finding":"privileged_change_chain", "event_ids":[x["event_id"] for x in (logon,account,membership,service,clear)],
                                        "host":logon["host"], "actor":logon.get("TargetUserName"),
                                        "new_account":account.get("TargetUserName"), "logon_id":logon["TargetLogonId"],
                                        "assessment":"escalate for verification; unauthorized intent and binary execution are not proven"})
    return results


def render_timeline(events):
    lines = ["# Generated timeline — synthetic data", "", "| UTC | Event | Host | Observation |", "|---|---|---|---|"]
    for e in validate(events):
        observation = f"{e['outcome']}: {e['username']} from {e['source_ip']}" if "outcome" in e else f"EventID {e['EventID']} · {e.get('summary','')}"
        safe = lambda s: str(s).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        lines.append("| "+" | ".join(safe(x) for x in (parse_time(e["timestamp"]).isoformat().replace("+00:00","Z"),e["event_id"],e["host"],observation))+" |")
    return "\n".join(lines)+"\n"


def replay(check=False):
    manifest = json.loads((ROOT/"evidence-manifest.json").read_text())
    for relative, expected in manifest.items():
        actual = hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()
        if actual != expected: raise ValueError(f"evidence changed: {relative}")
    total = 0
    for name, function, filename in (("01-authentication",authentication_findings,"auth.csv"),("02-windows-changes",windows_findings,"windows.jsonl")):
        folder = ROOT
        with (folder/filename).open(encoding="utf-8",newline="") as f:
            events = list(csv.DictReader(f)) if filename.endswith("csv") else [json.loads(line) for line in f if line.strip()]
        findings = function(events)
        expected = json.loads((ROOT/"expected-findings.json").read_text())[name]
        if findings != expected: raise AssertionError(f"unexpected findings in {name}")
        output = {"findings.json":json.dumps(findings,ensure_ascii=False,indent=2)+"\n", "timeline.md":render_timeline(events)}
        for filename, content in output.items():
            path = folder/(name+"-"+filename)
            if check:
                if path.read_text() != content: raise ValueError(f"stale output: {path}")
            else: path.write_text(content)
        total += len(events)
        print(f"{name}: {len(events)} events, {len(findings)} finding(s), evidence hashes OK")
    print(f"Reproduced {total} synthetic events. No live systems contacted.")


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    replay(parser.parse_args().check)
