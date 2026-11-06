"""Turn parsed aggregate reports into a per-sender view and a readiness verdict."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from dmarc_ready.parse import Record, Report

MIN_DAYS = 7
_SECONDS_PER_DAY = 86_400

SenderClass = Literal["aligned", "partly-aligned", "unaligned", "unauthenticated"]
Verdict = Literal["ready", "not-ready", "insufficient-data"]

EXPLANATION: dict[SenderClass, str] = {
    "aligned": "Passes DMARC. Safe under p=reject.",
    "partly-aligned": "Passes DMARC for only some messages. The rest would be rejected.",
    "unaligned": "Authenticates, but as a different domain. Legitimate services look like this; "
    "set up DKIM or a return-path for this domain before enforcing.",
    "unauthenticated": "Passes neither SPF nor DKIM for any domain. Usually forged mail or forwarding; "
    "p=reject is meant to block this.",
}


@dataclass
class Sender:
    source_ip: str
    messages: int = 0
    dmarc_pass: int = 0
    reporters: set[str] = field(default_factory=set)
    auth_domains: set[str] = field(default_factory=set)
    hostname: str = ""

    @property
    def sender_class(self) -> SenderClass:
        if self.dmarc_pass == self.messages:
            return "aligned"
        if self.dmarc_pass > 0:
            return "partly-aligned"
        if self.auth_domains:
            return "unaligned"
        return "unauthenticated"


@dataclass
class DomainSummary:
    domain: str
    policy: str
    reports: int
    first: int
    last: int
    senders: list[Sender]

    @property
    def messages(self) -> int:
        return sum(s.messages for s in self.senders)

    @property
    def dmarc_pass(self) -> int:
        return sum(s.dmarc_pass for s in self.senders)

    @property
    def days(self) -> float:
        return (self.last - self.first) / _SECONDS_PER_DAY

    @property
    def blockers(self) -> list[Sender]:
        return [s for s in self.senders if s.sender_class in ("partly-aligned", "unaligned")]

    @property
    def verdict(self) -> Verdict:
        if self.messages == 0 or self.days < MIN_DAYS:
            return "insufficient-data"
        return "not-ready" if self.blockers else "ready"


def analyse(reports: Iterable[Report]) -> list[DomainSummary]:
    """Group reports by policy domain, dropping duplicate deliveries of the same report."""
    seen: set[tuple[str, str]] = set()
    by_domain: dict[str, list[Report]] = {}
    for report in reports:
        key = (report.org, report.report_id)
        if key in seen:
            continue
        seen.add(key)
        by_domain.setdefault(report.domain, []).append(report)
    return [_summarise(domain, group) for domain, group in sorted(by_domain.items())]


def _summarise(domain: str, reports: list[Report]) -> DomainSummary:
    if not reports:
        raise AssertionError("a domain group is never empty")
    senders: dict[str, Sender] = {}
    for report in reports:
        for record in report.records:
            sender = senders.setdefault(record.source_ip, Sender(record.source_ip))
            _add(sender, record, report.org)
    latest = max(reports, key=lambda r: r.end)
    ordered = sorted(senders.values(), key=lambda s: (-s.messages, s.source_ip))
    return DomainSummary(
        domain=domain,
        policy=latest.policy,
        reports=len(reports),
        first=min(r.begin for r in reports),
        last=latest.end,
        senders=ordered,
    )


def _add(sender: Sender, record: Record, reporter: str) -> None:
    sender.messages += record.count
    if record.dmarc_pass:
        sender.dmarc_pass += record.count
    sender.reporters.add(reporter)
    for result in (*record.dkim, *record.spf):
        if result.result == "pass":
            sender.auth_domains.add(result.domain)
    if not 0 <= sender.dmarc_pass <= sender.messages:
        raise AssertionError(f"{sender.source_ip}: pass count exceeds message count")
