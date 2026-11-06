from __future__ import annotations

import gzip
import io
import zipfile
from pathlib import Path

import pytest
from helpers import Row, report_xml

from dmarc_ready import parse
from dmarc_ready.parse import ReportError, load_xml_documents, parse_report


def test_parses_report_fields() -> None:
    report = parse_report(report_xml([Row("192.0.2.10", 5)]))
    assert report.org == "google.com"
    assert report.domain == "example.com"
    assert report.policy == "none"
    assert len(report.records) == 1
    record = report.records[0]
    assert (record.source_ip, record.count, record.dmarc_pass) == ("192.0.2.10", 5, True)
    assert record.dkim[0].selector == "s1"


def test_parses_namespaced_report() -> None:
    xml = report_xml([Row("192.0.2.10", 1)], namespace="urn:ietf:params:xml:ns:dmarc-2.0")
    assert parse_report(xml).records[0].count == 1


def test_dmarc_pass_needs_one_aligned_mechanism() -> None:
    report = parse_report(
        report_xml([Row("192.0.2.1", 1, dkim="fail", spf="pass"), Row("192.0.2.2", 1, "fail", "fail")])
    )
    assert [r.dmarc_pass for r in report.records] == [True, False]


def test_rejects_entity_expansion() -> None:
    bomb = b'<?xml version="1.0"?><!DOCTYPE f [<!ENTITY a "aaaa">]><feedback>&a;</feedback>'
    with pytest.raises(ReportError, match="unsafe"):
        parse_report(bomb)


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        (b"<other/>", "expected <feedback>"),
        (b"<feedback><report_metadata/></feedback>", "missing"),
        (b"not xml", "not well-formed"),
    ],
)
def test_rejects_malformed_reports(xml: bytes, message: str) -> None:
    with pytest.raises(ReportError, match=message):
        parse_report(xml)


def test_rejects_negative_count() -> None:
    with pytest.raises(ReportError, match="non-negative"):
        parse_report(report_xml([Row("192.0.2.1", -1)]))


def test_loads_gzip_and_zip(tmp_path: Path) -> None:
    xml = report_xml([Row("192.0.2.10", 1)])
    gz = tmp_path / "r.xml.gz"
    gz.write_bytes(gzip.compress(xml))
    zipped = tmp_path / "r.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("r.xml", xml)
    zipped.write_bytes(buf.getvalue())
    assert load_xml_documents(gz) == [xml]
    assert load_xml_documents(zipped) == [xml]


def test_caps_decompressed_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse, "MAX_XML_BYTES", 100)
    path = tmp_path / "big.xml.gz"
    path.write_bytes(gzip.compress(b"a" * 1_000))
    with pytest.raises(ReportError, match="larger than"):
        load_xml_documents(path)


def test_caps_zip_members(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(parse.MAX_ZIP_MEMBERS + 1):
            zf.writestr(f"{i}.xml", b"<feedback/>")
    path = tmp_path / "many.zip"
    path.write_bytes(buf.getvalue())
    with pytest.raises(ReportError, match="more than"):
        load_xml_documents(path)


def test_corrupt_gzip_is_a_report_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.gz"
    path.write_bytes(b"\x1f\x8bnot really gzip")
    with pytest.raises(ReportError, match="corrupt gzip"):
        load_xml_documents(path)
