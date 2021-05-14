from scapy.all import *

def process_packet(pkt):
    print(pkt.summary())
    pkt.show()


packets=rdpcap("mypcap.pcap")

for packet in packets:
    print(packet.show2())

# a=sniff(filter="tcp")
# a.nsummary()

