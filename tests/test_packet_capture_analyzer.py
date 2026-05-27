import unittest

from packet_capture_analyzer import analyze_packet_lines


class PacketCaptureAnalyzerTests(unittest.TestCase):
    def test_analyze_packet_lines_counts_protocols_and_risky_ports(self):
        lines = [
            "IP 10.0.0.5.51514 > 10.0.0.10.3389: Flags [S], seq 1, win 65535, length 0",
            "IP 10.0.0.8.52525 > 10.0.0.9.53: UDP, length 42",
            "IP 10.0.0.4 > 10.0.0.1: ICMP echo request, id 1, seq 1, length 64",
            "IP 10.0.0.5.51515 > 10.0.0.10.443: Flags [P.], length 12",
        ]

        result = analyze_packet_lines(lines)

        self.assertEqual(result["total_packets"], 4)
        self.assertEqual(result["protocol_counts"]["TCP"], 2)
        self.assertEqual(result["protocol_counts"]["UDP"], 1)
        self.assertEqual(result["protocol_counts"]["ICMP"], 1)
        self.assertEqual(len(result["high_risk_alerts"]), 1)
        self.assertEqual(result["high_risk_alerts"][0]["port"], "3389")
        self.assertEqual(result["top_source_ips"][0], ("10.0.0.5", 2))

    def test_ignores_blank_lines(self):
        result = analyze_packet_lines(["", "   ", "\n"])
        self.assertEqual(result["total_packets"], 0)
        self.assertEqual(result["protocol_counts"], {})
        self.assertEqual(result["high_risk_alerts"], [])


if __name__ == "__main__":
    unittest.main()
