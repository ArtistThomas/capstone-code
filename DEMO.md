# Capstone Demo — Cybersecurity Packet Capture Analyzer

--- 

## 1. Overview — What I built and the problem it solves

**Problem.** Security analysts often stare at raw packet capture text from tools like
`tcpdump`. It's dense, line-by-line, and hard to triage quickly: *Which protocols
dominate? Who is talking the most? Is anyone hitting risky services like Telnet or RDP?*

**What I built.** A small Python command-line tool that reads `tcpdump`-style capture
text and produces a quick triage summary:

- **Protocol breakdown** — counts of TCP, UDP, ICMP, and OTHER.
- **Top source IPs** — the chattiest hosts in the capture.
- **High-risk alerts** — flags traffic destined for commonly abused service ports:
  Telnet (`23`), RDP (`3389`), VNC (`5900`), and SMB (`445`).

It prints a readable report by default and can emit JSON (`--json`) to pipe into other
tooling.

> It turns a wall of packet text into a one-screen triage view.

---

## 2. AI Usage — How I used AI tools/agents

- **GitHub Copilot generated most of the code from prompts.** I described the goal
  (parse tcpdump lines, count protocols, flag risky ports) and Copilot scaffolded the
  parsing functions, regex patterns, and the CLI entry point.
- **Copilot Chat / agent authored files end to end.** Beyond autocomplete, I used the
  chat/agent workflow to create and edit whole files — the analyzer, the unit tests,
  the sample capture, and this demo document.
- **Iterative prompting.** I refined output through follow-up prompts: e.g., adding a
  human-readable report mode alongside JSON, and adding a `--json` flag without breaking
  the existing API.

> AI handled the boilerplate and regex so I could focus on *what* to
> detect and *how* to present it.

---

## 3. Key Learnings — What worked well

- **Fast scaffolding.** Going from idea to a working CLI was quick because AI handled
  the repetitive structure (arg parsing, regex, counters).
- **Test-backed confidence.** Unit tests (`tests/`) let me change the output format
  safely — the core `analyze_packet_lines()` logic stayed verified while I added the
  readable report.
- **Separation of concerns.** Keeping analysis (`analyze_packet_lines`) separate from
  presentation (`format_report`) made the JSON vs. text modes trivial to support.
- **Prompting is a skill.** Specific, constrained prompts ("keep the existing function
  signature", "add a flag, don't change the default behavior") produced far better
  results than vague ones.

---

## 4. Issues Encountered — Challenges and limitations

- **Regex fragility.** Parsing relies on `tcpdump`'s text format. Unusual or differently
  formatted lines can be miscounted or land in `OTHER`.
- **Format lock-in.** It only understands `tcpdump`-style text — not raw `.pcap` files
  or other capture tools.
- **No live capture.** The tool analyzes exported text; it doesn't sniff traffic itself.
- **Heuristic detection.** "High-risk" is a fixed port list, not behavioral analysis, so
  it can miss attacks on non-standard ports and flag benign admin traffic.
- **Documentation drift.** The README originally referenced a `sample_capture.txt` that
  didn't exist — a reminder to keep docs and code in sync (now fixed).

---

## 5. Potential Improvements — What I'd do next

- **Real `.pcap` support** using a library like `scapy` or `pyshark`.
- **Behavioral detection** — port-scan detection (one source hitting many ports) and
  traffic-volume spikes, instead of just a static port list.
- **Richer reporting** — CSV/HTML export, or a small summary chart.
- **Configurable risk list** — let users supply their own watched ports via a flag or
  config file.
- **Packaging** — turn it into an installable CLI (`pip install`) with `argparse` for
  proper help text and options.