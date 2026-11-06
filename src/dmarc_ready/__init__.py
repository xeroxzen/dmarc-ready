"""Is this domain ready for DMARC p=reject?"""

from dmarc_ready.analyse import DomainSummary, Sender, analyse
from dmarc_ready.parse import Report, ReportError, load_xml_documents, parse_report

__all__ = [
    "DomainSummary",
    "Report",
    "ReportError",
    "Sender",
    "analyse",
    "load_xml_documents",
    "parse_report",
]
