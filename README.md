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

## Known "Bugs" (Intentional)

- **UDP scan says "No hosts responded"** — Not a bug. UDP is just shy.
- **OS Detection says "Unknown"** — Your router is playing hard to get.
- **250 threads make your phone warm** — That's not a bug, that's a feature. Free hand warmer.
- **`--udp` on Android** — Android said "no" before you even asked.
- **Exported CSV opens in Excel** — We're sorry in advance.

## Easter Eggs

- Type `java SanderScan -h` and read carefully.
- There's a comment in the code that says "don't touch this".
- If you find a real bug, congrats. You're hired.

This project was built with AI. Here's the breakdown:

| Role | Contributor |
|-------|-------------|
| 💡 **Idea & Architecture** | Me (human) |
| ✅ **Boolean Logic Verification** | ![Qwen](https://img.shields.io/badge/Qwen_3.8-6A0DAD?style=flat-square) |
| 🐛 **Realtime Code Debugging** | ![DeepSeek](https://img.shields.io/badge/DeepSeek_v4.1_Pro-0A66C2?style=flat-square) |
| 📁 **Repo Structure & README** | ![Copilot](https://img.shields.io/badge/GitHub_Copilot-181717?style=flat-square&logo=github) |

<p align="center">
  <img src="https://img.shields.io/badge/Made_with-AI_Collaboration-FF6B6B?style=for-the-badge" />
  <img src="https://img.shields.io/badge/From-Indonesia-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Device-Phone_Only-blue?style=for-the-badge" />
</p>

---

**Honesty is number one.** I didn't write every line myself. I used AI as a partner, not a replacement. The idea is mine, the execution was assisted. If you think that's "cheating", that's your problem. I'm proud of what I built. 🗿

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
