# SanderScan

LAN & Port Scanner for PC and Termux.

## Versi
- **PC** — Full fitur (TCP + UDP + ARP)
- **Termux** — TCP only (keterbatasan Android)

## Fitur
- Auto-detect jaringan
- Multi-thread scanning
- Banner grabbing
- MAC vendor detection
- OS Detection
- Export CSV & JSON

## Cara Pakai
```bash
javac SanderScan.java
java SanderScan
java SanderScan 192.168.1.1 22,80,443
java SanderScan 192.168.1.0/24
