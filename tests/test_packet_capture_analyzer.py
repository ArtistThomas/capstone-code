import unittest

from packet_capture_analyzer import analyze_packet_lines, format_report


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

    def test_analyze_packet_lines_ignores_blank_lines(self):
        result = analyze_packet_lines(["", "   ", "\n"])
        self.assertEqual(result["total_packets"], 0)
        self.assertEqual(result["protocol_counts"], {})
        self.assertEqual(result["top_source_ips"], [])
        self.assertEqual(result["high_risk_alerts"], [])


class FormatReportTests(unittest.TestCase):
    def test_format_report_includes_key_sections(self):
        lines = [
            "IP 10.0.0.5.51514 > 10.0.0.10.3389: Flags [S], seq 1, win 65535, length 0",
            "IP 10.0.0.8.52525 > 10.0.0.9.53: UDP, length 42",
        ]

        report = format_report(analyze_packet_lines(lines))

        self.assertIn("Packet Capture Analysis", report)
        self.assertIn("Total packets: 2", report)
        self.assertIn("Protocol breakdown:", report)
        self.assertIn("Top source IPs:", report)
        self.assertIn("High-risk alerts: 1", report)
        self.assertIn("port 3389", report)

    def test_format_report_handles_empty_analysis(self):
        report = format_report(analyze_packet_lines([]))

        self.assertIn("Total packets: 0", report)
        self.assertIn("High-risk alerts: 0", report)


if __name__ == "__main__":
    unittest.main()
