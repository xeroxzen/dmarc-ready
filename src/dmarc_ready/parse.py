"""Load and parse DMARC aggregate (rua) reports.

Reports arrive as .xml, .xml.gz or .zip attachments from parties you don't control, so every input is
treated as hostile: sizes are capped before and after decompression, and XML is parsed with DTDs and
entities forbidden.
"""

from __future__ import annotations

import gzip
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_XML_BYTES = 50 * 1024 * 1024
MAX_ZIP_MEMBERS = 10
MAX_RECORDS = 100_000

_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"


class ReportError(ValueError):
    """The file is not a readable DMARC aggregate report."""


@dataclass(frozen=True)
class AuthResult:
    domain: str
    result: str
    selector: str = ""


@dataclass(frozen=True)
class Record:
    source_ip: str
    count: int
    disposition: str
    header_from: str
    dkim_aligned: bool
    spf_aligned: bool
    dkim: tuple[AuthResult, ...]
    spf: tuple[AuthResult, ...]

    @property
    def dmarc_pass(self) -> bool:
        return self.dkim_aligned or self.spf_aligned


@dataclass(frozen=True)
class Report:
    org: str
    report_id: str
    begin: int
    end: int
    domain: str
    policy: str
    records: tuple[Record, ...]


def load_xml_documents(path: Path) -> list[bytes]:
    """Return the XML documents in a .xml, .xml.gz or .zip file."""
    with path.open("rb") as fh:
        raw = fh.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ReportError(f"file is larger than {MAX_FILE_BYTES} bytes")
    if raw.startswith(_ZIP_MAGIC):
        return _unzip(raw)
    if raw.startswith(_GZIP_MAGIC):
        return [_gunzip(raw)]
    return [raw]


def _bounded_read(stream: IO[bytes] | gzip.GzipFile) -> bytes:
    data = stream.read(MAX_XML_BYTES + 1)
    if len(data) > MAX_XML_BYTES:
        raise ReportError(f"decompressed report is larger than {MAX_XML_BYTES} bytes")
    return data


def _gunzip(raw: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            return _bounded_read(gz)
    except (OSError, EOFError) as exc:
        raise ReportError(f"corrupt gzip data: {exc}") from exc


def _unzip(raw: bytes) -> list[bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            if len(members) > MAX_ZIP_MEMBERS:
                raise ReportError(f"zip holds more than {MAX_ZIP_MEMBERS} files")
            docs = []
            for member in members:
                with zf.open(member) as fh:
                    docs.append(_bounded_read(fh))
            return docs
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise ReportError(f"corrupt zip data: {exc}") from exc


def parse_report(xml: bytes) -> Report:
    """Parse one aggregate report document."""
    try:
        root = fromstring(xml, forbid_dtd=True)
    except (ParseError, DefusedXmlException) as exc:
        raise ReportError(f"not well-formed or unsafe XML: {exc}") from exc
    _strip_namespaces(root)
    if root.tag != "feedback":
        raise ReportError(f"root element is <{root.tag}>, expected <feedback>")
    meta = _child(root, "report_metadata")
    policy = _child(root, "policy_published")
    begin = _int(_text(meta, "date_range/begin"))
    end = _int(_text(meta, "date_range/end"))
    if begin > end:
        raise ReportError("date range begins after it ends")
    records = root.findall("record")
    if len(records) > MAX_RECORDS:
        raise ReportError(f"report has more than {MAX_RECORDS} records")
    return Report(
        org=_text(meta, "org_name"),
        report_id=_text(meta, "report_id"),
        begin=begin,
        end=end,
        domain=_text(policy, "domain").lower(),
        policy=_text(policy, "p").lower(),
        records=tuple(_record(r) for r in records),
    )


def _strip_namespaces(root: Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.split("}", 1)[1]


def _record(el: Element) -> Record:
    row = _child(el, "row")
    evaluated = _child(row, "policy_evaluated")
    count = _int(_text(row, "count"))
    auth = el.find("auth_results")
    return Record(
        source_ip=_text(row, "source_ip"),
        count=count,
        disposition=_text(evaluated, "disposition").lower(),
        header_from=_text(el, "identifiers/header_from").lower(),
        dkim_aligned=_text(evaluated, "dkim").lower() == "pass",
        spf_aligned=_text(evaluated, "spf").lower() == "pass",
        dkim=_auth(auth, "dkim", with_selector=True),
        spf=_auth(auth, "spf", with_selector=False),
    )


def _auth(auth: Element | None, kind: str, *, with_selector: bool) -> tuple[AuthResult, ...]:
    if auth is None:
        return ()
    results = []
    for el in auth.findall(kind):
        selector = _optional_text(el, "selector") if with_selector else ""
        results.append(AuthResult(_text(el, "domain").lower(), _text(el, "result").lower(), selector))
    return tuple(results)


def _child(el: Element, path: str) -> Element:
    found = el.find(path)
    if found is None:
        raise ReportError(f"missing <{path}> under <{el.tag}>")
    return found


def _text(el: Element, path: str) -> str:
    value = (_child(el, path).text or "").strip()
    if not value:
        raise ReportError(f"empty <{path}> under <{el.tag}>")
    return value


def _optional_text(el: Element, path: str) -> str:
    found = el.find(path)
    return (found.text or "").strip() if found is not None else ""


def _int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ReportError(f"expected a whole number, got {value!r}") from exc
    if number < 0:
        raise ReportError(f"expected a non-negative number, got {number}")
    return number
