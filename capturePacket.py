import pyshark

cap = pyshark.LiveCapture(output_file="packets.pcap")

print("Enter the time to sniff packets in seconds")

t = int(input())

cap.sniff(timeout=t)

cap.close()
