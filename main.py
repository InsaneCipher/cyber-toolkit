from scapy.all import sniff
from collections import Counter

counter = Counter()


def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        key = (ip_layer.src, ip_layer.dst)
        counter[key] += 1


# Capture for 30s
print("Sniffing...")
sniff(prn=packet_callback, timeout=30)

print("\nTop connections:")
for (src, dst), count in counter.most_common(10):
    print(f"{src} -> {dst}: {count} packets")
