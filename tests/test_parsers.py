import json

from soc_lab.parsers import firewall, sshd, windows


def test_sshd_failed_invalid_user():
    e = sshd.parse_line("2026-10-14T03:05:12Z srv-web-01 sshd[4312]: Failed password for invalid user "
                        "admin from 203.0.113.77 port 51234 ssh2\n")
    assert (e.source, e.category, e.outcome, e.user) == ("sshd", "authentication", "failure", "admin")
    assert e.src_ip == "203.0.113.77" and e.src_port == 51234
    assert e.dst_ip == "10.10.2.10" and e.dst_port == 22
    assert e.extra["invalid_user"] is True


def test_sshd_accepted_publickey():
    e = sshd.parse_line("2026-10-14T10:00:00Z srv-web-01 sshd[1]: Accepted publickey for deploy "
                        "from 10.10.5.10 port 40000 ssh2")
    assert e.outcome == "success" and e.event_code == "sshd_accepted"
    assert e.extra == {"auth_method": "publickey", "invalid_user": False, "pid": 1}


def test_sshd_ignores_non_auth_lines():
    assert sshd.parse_line("2026-10-14T10:00:00Z srv-web-01 sshd[1]: Connection closed by 10.0.0.1") is None
    assert sshd.parse_line("basura") is None


def test_firewall_line():
    e = firewall.parse_line("2026-10-14T02:47:03Z fw01 action=deny proto=tcp src=203.0.113.77 spt=40112 "
                            "dst=10.10.2.10 dpt=3389 bytes=0 rule=default-deny")
    assert (e.outcome, e.protocol, e.dst_port, e.extra["rule"]) == ("denied", "tcp", 3389, "default-deny")
    assert firewall.parse_line("2026-10-14T02:47:03Z fw01 sin pares") is None


def _win(event_id, data, computer="EXCH01.corp.local", channel="Security"):
    return json.dumps({"TimeCreated": "2026-10-14T11:02:10Z", "EventID": event_id, "Channel": channel,
                       "Computer": computer, "EventData": data})


def test_windows_4625():
    e = windows.parse_line(_win(4625, {"TargetUserName": "r.medina", "IpAddress": "198.51.100.66",
                                       "IpPort": "50211", "LogonType": 8, "Status": "0xC000006D",
                                       "SubStatus": "0xC000006A"}))
    assert (e.event_code, e.outcome, e.host, e.logon_type) == ("4625", "failure", "EXCH01", 8)
    assert e.extra["sub_status"] == "0xC000006A" and e.dst_ip == "10.10.2.20"


def test_windows_4624_without_ip():
    e = windows.parse_line(_win(4624, {"TargetUserName": "svc_sql", "IpAddress": "-", "IpPort": "-",
                                       "LogonType": 5}, computer="DB01.corp.local"))
    assert e.src_ip is None and e.src_port is None and e.outcome == "success"


def test_windows_7045_and_unknown():
    e = windows.parse_line(_win(7045, {"ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe",
                                       "AccountName": "LocalSystem"}, computer="DB01.corp.local", channel="System"))
    assert e.category == "service" and e.service_name == "PSEXESVC"
    assert e.get("extra.image_path").endswith("PSEXESVC.exe")
    assert windows.parse_line(_win(4688, {})) is None
    assert windows.parse_line("   ") is None


def test_event_roundtrip(lab):
    from soc_lab.schema import Event

    for e in lab["events"][:50]:
        assert Event.from_dict(e.to_dict()) == e
