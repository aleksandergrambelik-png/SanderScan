# SanderScan

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20PC-orange)

> **"Scan your own network. Don't be a jerk."**

LAN & Port Scanner for PC and Termux. Built from a phone, for a phone.

## Why?

Because sometimes you just want to know what's on your WiFi.
And because `nmap` is overkill when all you need is a quick scan.

## Features
- Auto-detect network
- Multi-thread scanning (250 threads)
- Banner grabbing (HTTP, Telnet, etc.)
- MAC vendor detection
- OS Detection (TTL + vendor guess)
- Export to CSV & JSON

## Quick Start

```bash
git clone https://github.com/aleksandergrambelik-png/SanderScan.git
cd SanderScan/termux
javac SanderScan.java
java SanderScan 192.168.1.1 22,80,443

Disclaimer

⚠️ WARNING — DANGEROUS TOOL

This tool can cause REAL DAMAGE if misused.
Unauthorized use is a CRIMINAL OFFENSE.

Use only on your own network.

License

MIT License — see LICENSE file.

---

Made with ❤️ and too much coffee, from a phone.

```
