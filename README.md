# Cybersecurity Packet Capture Analyzer (Capstone Demo)

This repository now contains a small, beginner-friendly cybersecurity capstone project you can demo:

- Analyze packet capture text exported from tools like `tcpdump`
- Count packet volume by protocol (`TCP`, `UDP`, `ICMP`, `OTHER`)
- Flag traffic on common high-risk ports (for example: `23`, `3389`, `5900`)

## Why this fits your bootcamp capstone

It is:
- practical for cybersecurity workflows
- easy to demo live with sample packet data
- simple enough to extend with AI coding assistants

## Quick start

Use Python 3:

```bash
python packet_capture_analyzer.py sample_capture.txt
```

If you do not pass a file, the tool reads packet lines from standard input.

## Input format

The analyzer expects tcpdump-style lines, for example:

```text
IP 10.0.0.5.51514 > 10.0.0.10.3389: Flags [S], seq 1, win 65535, length 0
IP 10.0.0.8.52525 > 10.0.0.9.53: UDP, length 42
IP 10.0.0.4 > 10.0.0.1: ICMP echo request, id 1, seq 1, length 64
```

## Running tests

```bash
python -m unittest discover -s tests -v
```