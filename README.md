# Network-Packet-Sniffer
The Network Packet Sniffer is a tool for capturing and analyzing data packets on a network. It offers valuable insights into network traffic, making it useful for network administrators, security experts, and developers. The user-friendly interface simplifies packet capture and analysis, providing key network communication details.

import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
app = tk.Tk()
app.title("Network Packet Sniffer")
app.geometry("600x400")
text_area = scrolledtext.ScrolledText(app, wrap=tk.WORD, width=70, height=20)
text_area.pack(padx=10, pady=10)
def packet_sniffer(packet):
packet_info = ""
# Check for Ethernet frame
if Ether in packet:
    packet_info += "Ethernet Frame\n"
    # Check for IP layer
    if IP in packet:
        packet_info += f"Source IP: {packet[IP].src}\nDestination IP: {packet[IP].dst}\n\n"
        # Check for ARP layer
    elif ARP in packet:
        packet_info += f"ARP Packet\n\n"
        # If neither IP nor ARP, mark as unknown
    else:
        packet_info += "Unknown Packet\n\n"
# If not an Ethernet frame, mark as unknown
else:
        packet_info += "Unknown Packet\n\n"
text_area.insert(tk.END, packet_info)
text_area.see(tk.END)
def start_sniffing():
print("Starting sniffing...")
start_button.config(state=tk.DISABLED)
sniff(iface="eth0", prn=packet_sniffer, count=100)
print("Sniffing finished.")
start_button.config(state=tk.NORMAL)
start_button = tk.Button(app, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)
app.mainloop()
