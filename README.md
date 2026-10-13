# SanderScan

![Version](https://img.shields.io/badge/version-1.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20PC-orange)

> Scan your own network. Don't be a jerk.

SanderScan — LAN & port scanner ringan yang nyaman dipakai di phone dan PC.

## Quick highlights
- Auto-detect network
- Multi-thread (250 threads)
- Banner grabbing & MAC vendor
- Simple CSV / JSON export

## Quick start
```bash
git clone https://github.com/aleksandergrambelik-png/SanderScan.git
cd SanderScan/termux
javac SanderScan.java
java SanderScan 192.168.1.1 22,80,443
```

## Notes
- UDP scan kadang nggak respon — itu normal.
- OS detection pakai TTL + tebakan vendor.
- 250 threads = panasin phone (intended).

## About this repo
This project was built with help from AI tools as assistants, not replacements.

| Role | Contributor |
|------|-------------|
| Idea & Architecture | Me (human) |
| Logic checks | Qwen 3.8 |
| Debug help | DeepSeek v4.1 Pro |
| Repo & README help | GitHub Copilot |

---

**Honesty:** saya ngerjain inti dan kontrol kualitas — AI bantu saat perlu. Kalau itu masalah, yeh, itu pilihan kamu 😎

## Disclaimer
⚠️ WARNING — DANGEROUS TOOL  
Use only on networks you own. Unauthorized use may be illegal.

## License
MIT — see LICENSE

Made with ❤️ and too much coffee.