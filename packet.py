import pyshark

cap = pyshark.LiveCapture(output_file="packets.pcap")
cap.sniff(timeout=20)
# Start capturing packets
# print(f"Capturing packets on interface {interface}. Press Ctrl+C to stop...")
# try:
#     for packet in cap.sniff_continuously():
#         # Print a summary of each captured packet
#         print(packet.summary())
# except KeyboardInterrupt:
#     print("Capture stopped.")

# Close the packet capture when done
cap.close()
