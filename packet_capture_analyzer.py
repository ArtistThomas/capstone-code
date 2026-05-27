#!/usr/bin/env python3
"""Minimal packet-capture text analyzer for cybersecurity demos."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from typing import Dict, Iterable, List, Tuple, TypedDict

# Common high-risk service ports: Telnet, RDP, VNC, SMB.
HIGH_RISK_PORTS = {"23", "3389", "5900", "445"}
PROTOCOL_PATTERNS = {
    "TCP": re.compile(r"\bFlags \["),
    "UDP": re.compile(r"\bUDP\b"),
    "ICMP": re.compile(r"\bICMP\b"),
}
IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
DEST_PORT_PATTERN = re.compile(r">\s+\d{1,3}(?:\.\d{1,3}){3}\.(\d+):")


class HighRiskAlert(TypedDict):
    port: str
    line: str


class PacketAnalysis(TypedDict):
    total_packets: int
    protocol_counts: Dict[str, int]
    top_source_ips: List[Tuple[str, int]]
    high_risk_alerts: List[HighRiskAlert]


def _detect_protocol(line: str) -> str:
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        if pattern.search(line):
            return protocol
    return "OTHER"


def analyze_packet_lines(lines: Iterable[str]) -> PacketAnalysis:
    """Analyze tcpdump-style lines and return summary metrics."""
    protocols = Counter()
    high_risk_hits: List[HighRiskAlert] = []
    source_ips = Counter()
    total_packets = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        total_packets += 1
        protocols[_detect_protocol(line)] += 1

        # For expected tcpdump format ("IP source > dest"), first IP is source.
        ips = IP_PATTERN.findall(line)
        if ips:
            source_ips[ips[0]] += 1

        port_match = DEST_PORT_PATTERN.search(line)
        if port_match and port_match.group(1) in HIGH_RISK_PORTS:
            high_risk_hits.append({"port": port_match.group(1), "line": line})

    return {
        "total_packets": total_packets,
        "protocol_counts": dict(protocols),
        "top_source_ips": source_ips.most_common(5),
        "high_risk_alerts": high_risk_hits,
    }


def _read_input(path: str | None) -> List[str]:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.readlines()
    return sys.stdin.readlines()


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        results = analyze_packet_lines(_read_input(path))
    except OSError as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
