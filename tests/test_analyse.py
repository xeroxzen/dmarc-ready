from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import DAY, START, Row, report_xml

from dmarc_ready.analyse import analyse
from dmarc_ready.cli import main
from dmarc_ready.parse import parse_report

ALIGNED = Row("192.0.2.1", 100)
PARTLY = (Row("192.0.2.2", 30), Row("192.0.2.2", 10, dkim="fail", spf="fail"))
UNALIGNED = Row("198.51.100.7", 40, "fail", "fail", (("mailgun.org", "pass"),), (("mg.example.net", "pass"),))
FORGED = Row("203.0.113.9", 5, "fail", "fail", (), (("example.com", "fail"),))


def _summary(rows: list[Row], days: int = 10) -> object:
    [summary] = analyse([parse_report(report_xml(rows, days=days))])
    return summary


def test_classifies_each_kind_of_sender() -> None:
    [summary] = analyse([parse_report(report_xml([ALIGNED, *PARTLY, UNALIGNED, FORGED], days=10))])
    classes = {s.source_ip: s.sender_class for s in summary.senders}
    assert classes == {
        "192.0.2.1": "aligned",
        "192.0.2.2": "partly-aligned",
        "198.51.100.7": "unaligned",
        "203.0.113.9": "unauthenticated",
    }
    assert summary.messages == 185
    assert summary.dmarc_pass == 130
    assert summary.senders[0].source_ip == "192.0.2.1"


def test_verdicts() -> None:
    [ready] = analyse([parse_report(report_xml([ALIGNED, FORGED], days=10))])
    [blocked] = analyse([parse_report(report_xml([ALIGNED, UNALIGNED], days=10))])
    [short] = analyse([parse_report(report_xml([ALIGNED], days=3))])
    assert (ready.verdict, blocked.verdict, short.verdict) == ("ready", "not-ready", "insufficient-data")
    assert [s.source_ip for s in blocked.blockers] == ["198.51.100.7"]


def test_duplicate_report_counted_once() -> None:
    xml = report_xml([ALIGNED], days=10)
    [summary] = analyse([parse_report(xml), parse_report(xml)])
    assert (summary.reports, summary.messages) == (1, 100)


def test_span_covers_all_reports_and_latest_policy_wins() -> None:
    first = parse_report(report_xml([ALIGNED], report_id="a", days=4))
    second = parse_report(report_xml([ALIGNED], report_id="b", days=4, start=START + 4 * DAY))
    [summary] = analyse([second, first])
    assert summary.days == 8
    assert summary.verdict == "ready"


def test_groups_by_domain() -> None:
    a = parse_report(report_xml([ALIGNED], domain="example.com"))
    b = parse_report(report_xml([ALIGNED], domain="example.org", report_id="r2"))
    assert [s.domain for s in analyse([b, a])] == ["example.com", "example.org"]


def test_cli_text_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "ok.xml").write_bytes(report_xml([ALIGNED, UNALIGNED], days=10))
    assert main([str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "NOT READY" in out
    assert "authenticates as: mailgun.org, mg.example.net" in out


def test_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "ok.xml"
    path.write_bytes(report_xml([ALIGNED], days=10))
    assert main(["--json", str(path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "ready"
    assert data["senders"][0]["class"] == "aligned"


def test_cli_bad_file_is_status_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "good.xml").write_bytes(report_xml([ALIGNED], days=10))
    (tmp_path / "bad.xml").write_bytes(b"not xml")
    assert main([str(tmp_path)]) == 2
    assert "bad.xml: skipped" in capsys.readouterr().err
