"""dmarc-ready: is this domain ready for DMARC p=reject?

Reads DMARC aggregate (rua) reports and lists every sender that would lose mail if you enforced today.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dmarc_ready.analyse import EXPLANATION, DomainSummary, Sender, analyse
from dmarc_ready.parse import Report, ReportError, load_xml_documents, parse_report
from dmarc_ready.resolve import reverse_names

MAX_FILES = 5_000
SHOWN_PER_GROUP = 10

HEADLINE = {
    "ready": "READY for p=reject: every sender that authenticates is aligned.",
    "not-ready": "NOT READY: these senders would lose mail under p=reject.",
    "insufficient-data": "NOT ENOUGH DATA: collect at least 7 days of reports first.",
}


def _expand(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        files.extend(sorted(p for p in path.iterdir() if p.is_file()) if path.is_dir() else [path])
        if len(files) > MAX_FILES:
            raise ReportError(f"more than {MAX_FILES} files given")
    return files


def _load(files: list[Path]) -> tuple[list[Report], int]:
    reports: list[Report] = []
    errors = 0
    for path in files:
        try:
            reports.extend(parse_report(doc) for doc in load_xml_documents(path))
        except (ReportError, OSError) as exc:
            print(f"{path}: skipped: {exc}", file=sys.stderr)
            errors += 1
    return reports, errors


def _sender_line(s: Sender) -> str:
    name = f" ({s.hostname})" if s.hostname else ""
    rate = 100 * s.dmarc_pass / s.messages if s.messages else 0.0
    auth = f"  authenticates as: {', '.join(sorted(s.auth_domains))}" if s.auth_domains else ""
    return f"    {s.source_ip}{name}  {s.messages} msgs, {rate:.0f}% pass{auth}"


def _group(title: str, senders: list[Sender]) -> list[str]:
    if not senders:
        return []
    lines = [f"  {title} ({len(senders)}): {EXPLANATION[senders[0].sender_class]}"]
    lines.extend(_sender_line(s) for s in senders[:SHOWN_PER_GROUP])
    if len(senders) > SHOWN_PER_GROUP:
        lines.append(f"    ... and {len(senders) - SHOWN_PER_GROUP} more (use --json for all)")
    return lines


def _render(summary: DomainSummary) -> str:
    rate = 100 * summary.dmarc_pass / summary.messages if summary.messages else 0.0
    lines = [
        f"{summary.domain}: {HEADLINE[summary.verdict]}",
        f"  Policy now: p={summary.policy}. {summary.reports} reports covering {summary.days:.1f} days. "
        f"{summary.messages} messages, {rate:.1f}% pass DMARC.",
    ]
    by_class = {c: [s for s in summary.senders if s.sender_class == c] for c in EXPLANATION}
    lines += _group("Partly aligned", by_class["partly-aligned"])
    lines += _group("Unaligned", by_class["unaligned"])
    lines += _group("Unauthenticated", by_class["unauthenticated"])
    lines += _group("Aligned", by_class["aligned"])
    return "\n".join(lines)


def _as_json(summary: DomainSummary) -> str:
    senders = [
        {
            "source_ip": s.source_ip,
            "hostname": s.hostname,
            "messages": s.messages,
            "dmarc_pass": s.dmarc_pass,
            "class": s.sender_class,
            "auth_domains": sorted(s.auth_domains),
            "reporters": sorted(s.reporters),
        }
        for s in summary.senders
    ]
    return json.dumps(
        {
            "domain": summary.domain,
            "verdict": summary.verdict,
            "policy": summary.policy,
            "reports": summary.reports,
            "days": round(summary.days, 2),
            "messages": summary.messages,
            "dmarc_pass": summary.dmarc_pass,
            "senders": senders,
        }
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dmarc-ready", description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, metavar="PATH", help="report files or folders")
    parser.add_argument("--json", action="store_true", help="emit one JSON object per domain")
    parser.add_argument("--resolve", action="store_true", help="look up reverse-DNS names for sender IPs")
    args = parser.parse_args(argv)

    try:
        files = _expand(args.paths)
    except (ReportError, OSError) as exc:
        print(f"dmarc-ready: {exc}", file=sys.stderr)
        return 2
    reports, errors = _load(files)
    summaries = analyse(reports)
    if args.resolve:
        names = reverse_names([s.source_ip for summary in summaries for s in summary.senders])
        for sender in (s for summary in summaries for s in summary.senders):
            sender.hostname = names.get(sender.source_ip, "")
    for summary in summaries:
        print(_as_json(summary) if args.json else _render(summary) + "\n")
    if errors or not summaries:
        return 2
    return 0 if all(s.verdict == "ready" for s in summaries) else 1
