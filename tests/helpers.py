"""Builders for synthetic aggregate reports. All addresses are RFC 5737 documentation ranges."""

from __future__ import annotations

from dataclasses import dataclass

DAY = 86_400
START = 1_793_750_400


@dataclass(frozen=True)
class Row:
    ip: str
    count: int
    dkim: str = "pass"
    spf: str = "pass"
    auth_dkim: tuple[tuple[str, str], ...] = (("example.com", "pass"),)
    auth_spf: tuple[tuple[str, str], ...] = (("example.com", "pass"),)


def _row_xml(row: Row) -> str:
    dkim = "".join(
        f"<dkim><domain>{d}</domain><result>{r}</result><selector>s1</selector></dkim>"
        for d, r in row.auth_dkim
    )
    spf = "".join(f"<spf><domain>{d}</domain><result>{r}</result></spf>" for d, r in row.auth_spf)
    return (
        f"<record><row><source_ip>{row.ip}</source_ip><count>{row.count}</count>"
        f"<policy_evaluated><disposition>none</disposition><dkim>{row.dkim}</dkim><spf>{row.spf}</spf>"
        f"</policy_evaluated></row><identifiers><header_from>example.com</header_from></identifiers>"
        f"<auth_results>{dkim}{spf}</auth_results></record>"
    )


def report_xml(
    rows: list[Row],
    *,
    org: str = "google.com",
    report_id: str = "r1",
    days: int = 1,
    start: int = START,
    domain: str = "example.com",
    namespace: str = "",
) -> bytes:
    xmlns = f' xmlns="{namespace}"' if namespace else ""
    body = "".join(_row_xml(r) for r in rows)
    return (
        f'<?xml version="1.0"?><feedback{xmlns}><report_metadata><org_name>{org}</org_name>'
        f"<email>noreply@{org}</email><report_id>{report_id}</report_id>"
        f"<date_range><begin>{start}</begin><end>{start + days * DAY}</end></date_range></report_metadata>"
        f"<policy_published><domain>{domain}</domain><p>none</p><pct>100</pct></policy_published>"
        f"{body}</feedback>"
    ).encode()
