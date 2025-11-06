# Packet Sniffer

A lightweight packet sniffer written in *C using libpcap* that captures, analyzes, and prints details of Ethernet, IP, TCP, UDP, ARP, and ICMP packets. The project provides insights into how data flows across the network by parsing protocol headers and displaying field-level details.

---

## 🟩 Features
- Captures *Ethernet, IP, TCP, UDP, ARP, and ICMP* packets.
- Parses headers and extracts all important fields.
- Provides human-readable explanations for each field.
- Flowchart for code execution to understand packet parsing logic.
- Structured packet dissection for learning and debugging.

---

## 📦 Requirements
- Linux (Ubuntu recommended)
- gcc (C compiler)
- libpcap library

Install dependencies:
```bash
sudo apt-get update
sudo apt-get install gcc libpcap-dev -y
```

---

## ⚡ Compilation & Usage

Compile:

```bash
gcc sniffer.c -lpcap -o sniffer
```

Run with *sudo* (required for raw packet capture):

```bash
sudo ./sniffer
```

---

## 🔹 Ethernet Header

* *Destination MAC* – Physical address of the recipient device.
* *Source MAC* – Physical address of the sender.
* *EtherType* – Protocol encapsulated in payload:

  * 0x0800 → IPv4
  * 0x0806 → ARP
  * 0x86DD → IPv6

---

## 🔹 IP Header

* *Version* – IPv4 (4) or IPv6 (6).
* *IHL (Header Length)* – Number of 32-bit words in the header.
* *Type of Service (TOS/DSCP)* – Defines service priority.
* *Total Length* – Entire IP packet size (header + data).
* *Identification* – Unique packet ID for fragmentation.
* *Flags* – Fragmentation control (DF, MF).
* *Fragment Offset* – Position of fragment in original datagram.
* *Time to Live (TTL)* – Max hops allowed.
* *Protocol* – Upper layer protocol:

  * 6 → TCP
  * 17 → UDP
  * 1 → ICMP
* *Header Checksum* – Error checking.
* *Source/Destination IP Address* – Sender/Receiver IP.
* *Options* – Optional, for security/routing.

---

## 🔹 TCP Header

* *Source Port* – Sender’s port.
* *Destination Port* – Receiver’s port.
* *Sequence Number* – Byte ordering in stream.
* *Acknowledgment Number* – Confirms receipt of data.
* *Header Length* – TCP header size.
* *Flags:*

  * *URG*: Urgent pointer valid
  * *ACK*: Acknowledgment valid
  * *PSH*: Push data immediately
  * *RST*: Reset connection
  * *SYN*: Synchronize sequence numbers
  * *FIN*: Terminate connection
* *Window Size* – Flow control.
* *Checksum* – Error detection.
* *Urgent Pointer* – Data priority indicator.
* *Options* – Extra features (e.g., MSS).

---

## 🔹 UDP Header

* *Source Port* – Sender’s port.
* *Destination Port* – Receiver’s port.
* *Length* – UDP header + data length.
* *Checksum* – Error detection.

---
