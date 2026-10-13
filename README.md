# SanderScan

![Version](https://img.shields.io/badge/version-1.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20PC-orange)

> Scan your own network. Don't be a jerk.

SanderScan is a lightweight LAN and port scanner built for both phone and PC.

## Quick highlights
- Auto-detect network
- Multi-threaded scanning (250 threads)
- Banner grabbing and MAC vendor lookup
- CSV / JSON export

## Quick start
```bash
git clone https://github.com/aleksandergrambelik-png/SanderScan.git
cd SanderScan/termux
javac SanderScan.java
java SanderScan 192.168.1.1 22,80,443
```

## Notes
- UDP scans may appear empty — that is normal.
- OS detection uses TTL + vendor guessing.
- 250 threads can warm up your phone — intentional.

## About this project
This project was built with help from AI tools as assistants, not replacements.

| Role | Contributor |
|------|-------------|
| Idea & Architecture | Me (human) |
| Logic Checks | Qwen 3.8 |
| Debug Help | DeepSeek v4.1 Pro |
| Repo & README Help | GitHub Copilot |

---

**Honesty:** I handled the core work and quality control. AI helped when needed. If that bothers you, that's your call.

## Disclaimer
⚠️ WARNING — DANGEROUS TOOL

Use only on networks you own. Unauthorized use may be illegal.

## License
MIT — see LICENSE

Made with ❤️ and too much coffee.