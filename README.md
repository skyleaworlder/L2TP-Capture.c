# L2TP-Capture

:mag: Simple L2TP Packet Capture & Analysis

## Introduction

* pcap.h (mainly), arpa/inet.h (mainly) Used;
* Based on RFC-2661: Layer Two Tunneling Protocol "L2TP";
* BPF (Berkeley Packet Filter);
* Protocol Analysis;

Origin Repo is on my personal server.

[L2TPCAP](https://github.com/E011011101001/L2TPCAP) is the Repo that I cooperated with [@Eol](https://github.com/E011011101001) for **IS-Thoery Project-1**.

The content of this Repo is almost the same as [L2TPCAP](https://github.com/E011011101001/L2TPCAP), but this Repo tries to illustrate the develop-history of our packet-capture. (This Repo could exists, thanks to MIT License 233)

## Usage

```bash
gcc capture.c -o capture.exe

# e.g. ./capture.exe wlan0
./capture.exe [your-dev-name]
```
