# Task 1 — Basic Network Sniffer: Report

## What is a packet?

Whenever data travels over a network (browsing a website, sending a message, etc.), it doesn't
travel as one big blob. It gets broken into small chunks called **packets**. Each packet carries:

- A **source IP address** (who sent it) and **destination IP address** (who it's going to)
- A **protocol** identifying the type of traffic (e.g. TCP, UDP)
- **Port numbers**, which identify which application/service on each side is involved
  (for example, port 443 almost always means HTTPS — secure web traffic)
- The **payload**, the actual data being carried

## Tools used

- Python with the `scapy` library, which can capture and inspect live network traffic
- Npcap, the underlying driver that lets scapy access raw packets on Windows

## What I observed

I ran the sniffer script while browsing the web, and it printed live traffic passing through my
machine. For example:

```
[TCP] 160.79.104.10:443  ->  192.168.100.79:51750  (packet size: 107 bytes)
```

This shows my computer (`192.168.100.79`) communicating with a remote server (`160.79.104.10`) on
**port 443**, which is the standard port for **HTTPS** (encrypted web traffic).

## Key takeaway: encrypted traffic

When the script tried to preview the payload of these packets, it only showed scrambled,
unreadable characters (e.g. `0JX_g<*hq)f}`). This isn't a bug — it's expected, and it's actually
the most important thing I learned from this exercise: because the traffic is HTTPS, its content
is **encrypted end-to-end**, so even though I can see *who* is talking to *whom* and *how much*
data is being sent, I cannot see *what* is actually being said. This is very different from older,
unencrypted protocols like plain HTTP, where a sniffer could read the payload in plain text —
which is exactly why HTTPS adoption matters for privacy and security.

## Conclusion

This task showed me, hands-on, how network traffic is structured into packets, how to inspect
that traffic programmatically with Python, and why encryption (HTTPS) protects the content of
communications even when the metadata (who's talking to whom) is still visible to anyone
capturing traffic on the network.
