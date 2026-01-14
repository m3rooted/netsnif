# netsnif

![netsnif logo](assets/logo.svg)

Minimal Python network sniffer (raw socket) that prints parsed packets in real time and writes a PCAP capture file.

## Project metadata

- Description: Minimal Python network sniffer (raw socket) that prints parsed packets in real time and writes a PCAP capture file.
- Author: Nguyen Duong Quang
- Date: 2026-01-14

## Features

- Parses Ethernet, IPv4/IPv6 (with basic IPv6 extension header walking)
- Parses L4: ICMP/ICMPv6, TCP, UDP
- Attempts to decode HTTP when source/destination port is `80`
- Writes all frames to `capture.pcap`

## Requirements

- Python 3
- Linux (uses `socket.AF_PACKET`)
- Root privileges/capability to open a raw socket (e.g. run via `sudo`)

## Run

```bash
sudo python3 sniffer.py
```

## Output

- Prints packet details to the console
- Creates `capture.pcap` (open with Wireshark)

## Todo

- Improve HTTP parsing (currently only attempts when port = 80)
