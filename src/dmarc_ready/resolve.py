"""Optional reverse-DNS names for sender IPs, so '40.107.22.51' reads as an Outlook server."""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver
import dns.reversename

MAX_LOOKUPS = 200
TIMEOUT_SECONDS = 2.0


def reverse_names(ips: list[str]) -> dict[str, str]:
    """Look up PTR names for at most MAX_LOOKUPS addresses. Failures map to an empty string."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT_SECONDS
    names: dict[str, str] = {}
    for ip in ips[:MAX_LOOKUPS]:
        names[ip] = _ptr(resolver, ip)
    return names


def _ptr(resolver: dns.resolver.Resolver, ip: str) -> str:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    try:
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
    except dns.exception.DNSException:
        return ""
    return str(answer[0]).rstrip(".") if len(answer) else ""
