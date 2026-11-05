"""One invented row per shape, each `at` a given time, and how to send rows through the route."""

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List

INGEST = "/api/log-events/ingest"


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def ago(**delta: float) -> datetime:
    return now() - timedelta(**delta)


def iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def zeek_conn(at: datetime, **more: Any) -> Dict[str, Any]:
    return {
        "ts": at.timestamp(),
        "uid": "Cfake0001",
        "id.orig_h": "10.20.0.5",
        "id.orig_p": 50112,
        "id.resp_h": "10.20.0.9",
        "id.resp_p": 445,
        "proto": "tcp",
        "service": "smb",
        "conn_state": "SF",
        "orig_bytes": 1200,
        "resp_bytes": "-",
        **more,
    }


def zeek_dns(at: datetime) -> Dict[str, Any]:
    return {
        "ts": at.timestamp(),
        "id.orig_h": "10.20.0.5",
        "id.resp_h": "10.20.0.2",
        "id.resp_p": 53,
        "query": "quokka-update.example.net",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
        "answers": ["198.51.100.7"],
    }


def dns_log(at: datetime) -> Dict[str, Any]:
    return {
        "timestamp": iso(at),
        "client_ip": "10.20.0.6",
        "query_name": "wombat-cdn.example.org",
        "query_type": "AAAA",
        "rcode": "NXDOMAIN",
    }


def windows_logon(at: datetime) -> Dict[str, Any]:
    return {
        "Channel": "Security",
        "EventID": 4625,
        "TimeCreated": iso(at).replace("Z", ".1234567Z"),
        "Computer": "dc-rig-1.corp.example",
        "EventData": {
            "TargetUserName": "pat.quill",
            "IpAddress": "::ffff:10.20.0.7",
            "WorkstationName": "wks-rig-7",
            "LogonType": 3,
        },
    }


def winlogbeat_process(at: datetime) -> Dict[str, Any]:
    return {
        "@timestamp": iso(at),
        "winlog": {
            "channel": "Security",
            "event_id": "4688",
            "computer_name": "wks-rig-7",
            "event_data": {
                "SubjectUserName": "pat.quill",
                "NewProcessName": "C:\\Tools\\quokka.exe",
            },
        },
    }


def sysmon_process(at: datetime) -> Dict[str, Any]:
    return {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "UtcTime": at.strftime("%Y-%m-%d %H:%M:%S.123"),
        "Computer": "wks-rig-8",
        "User": "CORP\\sam.ridge",
        "Image": "C:\\Windows\\System32\\quokkahost.exe",
        "CommandLine": "quokkahost.exe -enc AAAA",
    }


def paloalto_csv_row(at: datetime) -> Dict[str, Any]:
    return {
        "Receive Time": at.strftime("%Y/%m/%d %H:%M:%S"),
        "Type": "TRAFFIC",
        "Source address": "10.20.0.5",
        "Destination address": "203.0.113.40",
        "Destination Port": "8443",
        "Source User": "CORP\\sam.ridge",
        "Application": "ssl",
        "Action": "deny",
        "Rule": "block-outbound",
    }


def crowdstrike_process(at: datetime) -> Dict[str, Any]:
    return {
        "event_simpleName": "ProcessRollup2",
        "timestamp": str(int(at.timestamp() * 1000)),
        "ComputerName": "wks-rig-9",
        "UserName": "lee.marsh",
        "ImageFileName": "\\Device\\HarddiskVolume3\\Tools\\wombat.exe",
        "CommandLine": "wombat.exe /quiet",
        "Severity": "4",
        "TechniqueId": "t1059.001",
    }


def entra_failed(at: datetime) -> Dict[str, Any]:
    return {
        "createdDateTime": iso(at),
        "userPrincipalName": "lee.marsh@corp.example",
        "ipAddress": "198.51.100.23",
        "appDisplayName": "Rig Portal",
        "status": {"errorCode": 50126, "failureReason": "Invalid password"},
        "location": {"city": "Testville"},
    }


def generic(at: datetime, **more: Any) -> Dict[str, Any]:
    return {
        "time": iso(at),
        "source": "RigApp Audit",
        "host": "app-rig-1",
        "user": "kit.vale",
        "action": "export",
        "severity": "warning",
        "message": "Exported the quokka report",
        "dst_ip": "not-an-address",
        **more,
    }


def jsonl(rows: Iterable[Any]) -> bytes:
    return "\n".join(json.dumps(r) for r in rows).encode()


def csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode()


def send(client, content: bytes, name: str = "events.jsonl", **form: str):
    return client.post(INGEST, files={"file": (name, content)}, data=form)


def make_case(case_id: str) -> None:
    from core.storage.models.case import Case
    from core.storage.unit_of_work import unit_of_work

    with unit_of_work() as session:
        session.add(Case(case_id=case_id, title="Logs test case"))
