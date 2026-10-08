import copy
import json
import unittest
from pathlib import Path
from replay import authentication_findings, windows_findings, validate, ROOT


class ReplayTests(unittest.TestCase):
    def events(self):
        return [json.loads(line) for line in (ROOT/'windows.jsonl').read_text().splitlines()]

    def test_chain_is_order_independent(self):
        events=self.events()
        self.assertEqual(1,len(windows_findings(events)))
        self.assertEqual(windows_findings(events),windows_findings(list(reversed(events))))

    def test_wrong_member_sid_breaks_chain(self):
        events=self.events()
        for e in events:
            if e['EventID']==4732:e['MemberSid']='S-1-5-21-100-200-300-9999'
        self.assertEqual([],windows_findings(events))

    def test_wrong_session_or_host_breaks_chain(self):
        for key,value in [('SubjectLogonId','0x999'),('host','other-host')]:
            events=self.events()
            for e in events:
                if e['EventID']==1102:e[key]=value
            self.assertEqual([],windows_findings(events))

    def test_late_event_breaks_chain(self):
        events=self.events()
        for e in events:
            if e['EventID']==1102:e['timestamp']='2026-10-02T12:00:00Z'
        self.assertEqual([],windows_findings(events))

    def test_missing_logon_does_not_guess_session(self):
        self.assertEqual([],windows_findings([e for e in self.events() if e['EventID']!=4624]))

    def test_duplicate_and_naive_time_are_rejected(self):
        events=self.events()
        with self.assertRaises(ValueError):validate(events+[events[0]])
        events[0]['timestamp']='2026-10-02T10:00:00'
        with self.assertRaises(ValueError):validate(events)


if __name__=='__main__':unittest.main()
