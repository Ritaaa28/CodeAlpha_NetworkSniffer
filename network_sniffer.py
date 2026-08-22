from scapy.all import sniff, IP, TCP, UDP


def analyze_packet(packet):
    """
    This function runs automatically for every packet that scapy
    captures.
    """

    
    
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        
        
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

        
        
        
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load
            try:
                text_preview = payload[:50].decode("utf-8", errors="ignore")
                if text_preview.strip():
                    print(f"    payload preview: {text_preview}")
            except Exception:
                pass  


if __name__ == "__main__":
    print("Starting packet capture... browse the web now. Press Ctrl+C to stop.\n")
    
    
    sniff(prn=analyze_packet, store=False, count=0)
