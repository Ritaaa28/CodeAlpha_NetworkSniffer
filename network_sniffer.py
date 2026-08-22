from scapy.all import sniff, IP, TCP, UDP


def analyze_packet(packet):
    """
    This function runs automatically for every packet that scapy
    captures. 'packet' is one single network packet.
    """

    # Every packet on the internet is wrapped in an IP layer, which
    # tells us who sent it and who it's going to.
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # The protocol number tells us what kind of traffic this is.
        # We check for the two most common ones: TCP and UDP.
        if TCP in packet:
            protocol_name = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif UDP in packet:
            protocol_name = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
        else:
            protocol_name = "OTHER"
            source_port = "?"
            destination_port = "?"

        print(f"[{protocol_name}] {source_ip}:{source_port}  ->  "
              f"{destination_ip}:{destination_port}  "
              f"(packet size: {len(packet)} bytes)")

        # Try to show a small preview of the raw payload, if there is
        # readable text in it (many packets are encrypted/binary, so
        # this will often just show gibberish or nothing - that's normal).
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            try:
                text_preview = payload[:50].decode("utf-8", errors="ignore")
                if text_preview.strip():
                    print(f"    payload preview: {text_preview}")
            except Exception:
                pass  # binary/encrypted data, nothing readable to show


if __name__ == "__main__":
    print("Starting packet capture... browse the web now. Press Ctrl+C to stop.\n")

    # sniff() is scapy's main function:
    #   prn=analyze_packet  -> call our function on every packet
    #   store=False         -> don't keep packets in memory (saves RAM)
    #   count=0              -> keep capturing until we stop it manually
    sniff(prn=analyze_packet, store=False, count=0)
