# SanderScan

LAN & Port Scanner for PC and Termux.

## Versions

- **PC** — Full features (TCP + UDP + ARP)
- **Termux** — TCP only (Android limitations)

## Features

- Auto-detect network
- Multi-thread scanning
- Banner grabbing
- MAC vendor detection
- OS Detection
- Export to CSV & JSON

## Usage

```bash
javac SanderScan.java
java SanderScan
java SanderScan 192.168.1.1 22,80,443
java SanderScan 192.168.1.0/24
