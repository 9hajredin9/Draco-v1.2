#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, DNS, DHCP, Ether, get_if_list, rdpcap, Raw, conf
import pandas as pd
import threading
import socket
import platform
from collections import defaultdict
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global variables
sniffing = False
packets_list = []  # Stores full Scapy packets
protocol_count = defaultdict(int)
last_update_time = 0
UPDATE_INTERVAL = 0.5  # Update GUI every 0.5 seconds
was_stopped = False

# Automatically detect an active network interface
def get_default_interface():
    interfaces = get_if_list()
    if not interfaces:
        return None
    for iface in interfaces:
        if iface != "lo" and iface != "loopback":
            try:
                if conf.iface == iface or socket.gethostbyname(socket.gethostname()) in [i[4] for i in socket.getaddrinfo(iface, None)]:
                    return iface
            except:
                continue
    return next((iface for iface in interfaces if iface != "lo" and iface != "loopback"), interfaces[0])

# Function to capture packets
def packet_callback(packet):
    global last_update_time
    if not sniffing:
        return

    if packet.haslayer(Ether) and (packet.haslayer(IP) or packet.haslayer(ARP)):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "HTTP" if packet[TCP].dport == 80 or packet[TCP].sport == 80 else "HTTPS" if packet[TCP].dport == 443 or packet[TCP].sport == 443 else "TCP"
        elif packet.haslayer(UDP):
            protocol = "DNS" if packet[UDP].dport == 53 or packet[UDP].sport == 53 else "DHCP" if packet[UDP].dport == 67 or packet[UDP].sport == 68 else "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        elif packet.haslayer(ARP):
            protocol = "ARP"

        has_raw = packet.haslayer(Raw)
        payload_preview = packet[Raw].load[:20] if has_raw else "No Raw layer"
        print(f"Packet captured: {protocol} | Has Raw: {has_raw} | Payload Preview: {payload_preview}")

        packet_data = {"packet": packet, "timestamp": timestamp, "protocol": protocol}
        packets_list.append(packet_data)
        protocol_count[protocol] += 1
        print(f"Total packets: {len(packets_list)}")

        current_time = time.time()
        if current_time - last_update_time >= UPDATE_INTERVAL:
            root.after(0, update_gui)
            last_update_time = current_time
            print(f"Scheduled GUI update at {timestamp}")

# Batch update GUI elements with scrollbar control
def update_gui():
    scrollbar_pos = tree_scrollbar.get()
    at_bottom = scrollbar_pos[1] >= 1.0 - 0.01

    start_index = len(tree.get_children())
    for i, packet_data in enumerate(packets_list[start_index:], start_index + 1):
        packet = packet_data["packet"]
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        tree.insert("", "end", values=(i, src_ip, dst_ip, packet_data["protocol"], packet_data["timestamp"]), tags=(packet_data["protocol"],))
        print(f"Added to table: {packet_data['protocol']} (Row: {i})")

    if at_bottom:
        tree.yview_moveto(1.0)

    update_protocol_stats()
    update_graph()

# Filter packets based on dropdown selection
def filter_packets(event=None):
    tree.delete(*tree.get_children())
    filter_protocol = packet_filter_combobox.get()
    displayed_packets = [p for p in packets_list if not filter_protocol or p["protocol"] == filter_protocol]
    for i, packet_data in enumerate(displayed_packets, 1):
        packet = packet_data["packet"]
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        tree.insert("", "end", values=(i, src_ip, dst_ip, packet_data["protocol"], packet_data["timestamp"]), tags=(packet_data["protocol"],))
    update_protocol_stats()

# Update protocol statistics
def update_protocol_stats():
    filter_protocol = packet_filter_combobox.get()
    displayed_packets = [p for p in packets_list if not filter_protocol or p["protocol"] == filter_protocol]
    total_count = len(packets_list)
    stat_text = f"Total Packets: {total_count} | Displayed: {len(displayed_packets)} | "
    stat_text += " | ".join(f"{proto}: {count}" for proto, count in protocol_count.items())
    total_packets_label.config(text=stat_text)
    status_label.config(text=f"Status: {'Sniffing' if sniffing else 'Stopped'} on {selected_interface}")

# Update real-time graph
def update_graph():
    ax.clear()
    protocols = list(protocol_count.keys())
    counts = list(protocol_count.values())
    bars = ax.bar(protocols, counts, color=['#00ff00', '#0000ff', '#ff0000', '#ffff00', '#808080'][:len(protocols)])
    ax.set_title("Protocol Distribution", color="white")
    ax.set_xticks(range(len(protocols)))
    ax.set_xticklabels(protocols, rotation=45, color="white")
    ax.tick_params(axis='y', colors='white')
    ax.set_facecolor('#2e2e2e')
    fig.set_facecolor('#1e1e1e')
    canvas.draw()

# Enhanced packet details with hex/ASCII payload and layer breakdown
def show_packet_details(event):
    print("Debug: Entering show_packet_details")
    selected_item = tree.selection()
    if not selected_item:
        print("Debug: No item selected in tree")
        return

    packet_info = tree.item(selected_item, "values")
    if not packet_info:
        print("Debug: No packet info retrieved from tree")
        return

    print(f"Debug: Packet info from tree: {packet_info}")
    src_ip, dst_ip, protocol, timestamp = packet_info[1], packet_info[2], packet_info[3], packet_info[4]

    selected_packet_data = next((p for p in packets_list if (p["packet"][IP].src if p["packet"].haslayer(IP) else "N/A") == src_ip and 
                                (p["packet"][IP].dst if p["packet"].haslayer(IP) else "N/A") == dst_ip and 
                                p["protocol"] == protocol and p["timestamp"] == timestamp), None)

    if not selected_packet_data:
        print("Debug: No matching packet found in packets_list")
        messagebox.showerror("Error", "Packet details not found.")
        return

    packet = selected_packet_data["packet"]
    print(f"Debug: Packet retrieved - Layers: {[layer.__class__.__name__ for layer in packet]}")

    src_mac = packet[Ether].src if packet.haslayer(Ether) else "N/A"
    dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "N/A"

    payload = packet[Raw].load if packet.haslayer(Raw) else b"No Payload"
    print(f"Debug: Payload check - Has Raw: {packet.haslayer(Raw)}, Payload: {payload[:20] if payload != b'No Payload' else 'No Payload'}")

    try:
        hostname = socket.gethostbyaddr(src_ip)[0] if src_ip != "N/A" else "N/A"
    except socket.herror:
        hostname = "Unknown"

    os_info = platform.system()

    packet_window = tk.Toplevel(root)
    packet_window.title("Packet Details")
    packet_window.geometry("800x600")
    packet_window.configure(bg="#1e1e1e")
    print("Debug: Packet window created")

    # Basic Info
    basic_frame = tk.Frame(packet_window, bg="#1e1e1e")
    basic_frame.pack(fill="x", padx=10, pady=5)
    packet_details_tree = ttk.Treeview(basic_frame, columns=("Attribute", "Value"), show="headings", style="Dark.Treeview", height=6)
    packet_details_tree.heading("Attribute", text="Attribute")
    packet_details_tree.heading("Value", text="Value")
    packet_details_tree.column("Attribute", width=150)
    packet_details_tree.column("Value", width=400)
    packet_details_tree.insert("", "end", values=("Source MAC", src_mac))
    packet_details_tree.insert("", "end", values=("Destination MAC", dst_mac))
    packet_details_tree.insert("", "end", values=("Protocol", protocol))
    packet_details_tree.insert("", "end", values=("Timestamp", timestamp))
    packet_details_tree.insert("", "end", values=("Hostname", hostname))
    packet_details_tree.insert("", "end", values=("System (OS)", os_info))
    packet_details_tree.pack(side="left", fill="x", expand=True)
    print("Debug: Basic info tree populated")

    # Layer Breakdown
    layers_frame = tk.LabelFrame(packet_window, text="Packet Layers", font=("Arial", 10, "bold"), fg="#00ff00", bg="#1e1e1e", bd=2)
    layers_frame.pack(fill="x", padx=10, pady=5)
    layers_tree = ttk.Treeview(layers_frame, columns=("Layer", "Details"), show="headings", style="Dark.Treeview", height=6)
    layers_tree.heading("Layer", text="Layer")
    layers_tree.heading("Details", text="Details")
    layers_tree.column("Layer", width=150)
    layers_tree.column("Details", width=400)

    current_layer = packet
    while current_layer:
        layer_name = current_layer.__class__.__name__
        details = []
        for field_name in current_layer.fields_desc:
            if field_name.name in current_layer.fields:
                field_value = current_layer.fields[field_name.name]
                details.append(f"{field_name.name}: {field_value}")
        layers_tree.insert("", "end", values=(layer_name, ", ".join(details)))
        current_layer = current_layer.payload if current_layer.payload else None
    layers_tree.pack(fill="x", expand=True)
    print("Debug: Layers tree populated")

    # Payload Section
    payload_frame = tk.LabelFrame(packet_window, text="Payload (Hex / ASCII)", font=("Arial", 10, "bold"), fg="#00ff00", bg="#1e1e1e", bd=2)
    payload_frame.pack(fill="both", expand=True, padx=10, pady=5)
    payload_text = tk.Text(payload_frame, height=10, bg="#2e2e2e", fg="white", font=("Courier", 10))
    payload_text.pack(fill="both", expand=True)

    # Display payload or fallback
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            hex_payload = payload.hex()
            ascii_payload = payload.decode("ascii", errors="replace").replace("\r", "").replace("\n", " ")
            hex_formatted = " ".join(hex_payload[i:i+2] for i in range(0, len(hex_payload), 2))
            payload_text.insert("end", f"Hex: {hex_formatted}\n\nASCII: {ascii_payload}")
            print("Debug: Payload displayed (Raw layer found)")
        else:
            payload_text.insert("end", "No payload available (No Raw layer)")
            print("Debug: No payload displayed (No Raw layer)")
        # Add full packet hex
        full_packet_hex = bytes(packet).hex()
        hex_formatted = " ".join(full_packet_hex[i:i+2] for i in range(0, len(full_packet_hex), 2))
        payload_text.insert("end", f"\n\nFull Packet Hex: {hex_formatted}")
    except Exception as e:
        payload_text.insert("end", f"Error displaying payload: {e}")
        print(f"Debug: Payload display failed - Error: {e}")

    payload_text.config(state="disabled")
    print("Debug: Payload text widget updated")

    # Footer
    footer_label = tk.Label(packet_window, text="DRACO - Packet Inspection", font=("Arial", 10, "bold"), fg="#00ff00", bg="#1e1e1e")
    footer_label.pack(side="bottom", fill="x", pady=5)
    print("Debug: Footer added, exiting show_packet_details")

# Start/stop sniffing
def start_stop_sniffing():
    global sniffing, selected_interface, packets_list, protocol_count, was_stopped
    if sniffing:
        sniffing = False
        start_stop_button.config(text="Start Sniffing", bg="#006400")
        was_stopped = True
    else:
        if not selected_interface:
            messagebox.showerror("Error", "No network interface detected.")
            return
        if not was_stopped:
            packets_list.clear()
            protocol_count.clear()
            tree.delete(*tree.get_children())
            packet_filter_combobox.set("")
        print(f"Starting sniff with capture filter: {traffic_filter_combobox.get()}")
        sniffing = True
        start_stop_button.config(text="Stop Sniffing", bg="#8b0000")
        traffic_filter = traffic_filter_combobox.get() or None
        threading.Thread(target=sniff_packets, args=(selected_interface, traffic_filter), daemon=True).start()

# Start new with confirmation popup
def start_new():
    def confirm_yes():
        global sniffing, packets_list, protocol_count, was_stopped
        sniffing = False
        packets_list.clear()
        protocol_count.clear()
        tree.delete(*tree.get_children())
        packet_filter_combobox.set("")
        was_stopped = False
        start_stop_button.config(text="Start Sniffing", bg="#006400")
        confirm_window.destroy()
        start_stop_sniffing()

    def confirm_no():
        confirm_window.destroy()

    confirm_window = tk.Toplevel(root)
    confirm_window.title("Confirm")
    confirm_window.geometry("250x120")
    confirm_window.configure(bg="black")
    confirm_window.resizable(False, False)
    confirm_window.attributes("-topmost", True)

    confirm_window.update_idletasks()
    width = confirm_window.winfo_width()
    height = confirm_window.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    confirm_window.geometry(f"{width}x{height}+{x}+{y}")

    label = tk.Label(confirm_window, text="Are you sure?", font=("Arial", 12), fg="white", bg="black")
    label.pack(pady=20)

    button_frame = tk.Frame(confirm_window, bg="black")
    button_frame.pack(pady=10)

    yes_button = tk.Button(button_frame, text="Yes", command=confirm_yes, bg="red", fg="black", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5)
    yes_button.grid(row=0, column=0, padx=5)

    no_button = tk.Button(button_frame, text="No", command=confirm_no, bg="green", fg="white", font=("Arial", 10, "bold"), relief="flat", padx=10, pady=5)
    no_button.grid(row=0, column=1, padx=5)

def sniff_packets(interface, traffic_filter):
    while sniffing:
        try:
            sniff(prn=packet_callback, store=False, iface=interface, filter=traffic_filter, count=0, timeout=1)
        except PermissionError:
            root.after(0, lambda: messagebox.showerror("Error", "Permission denied. Run with sudo/admin privileges."))
            stop_sniffing()
            break
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", f"Sniffing failed: {e}"))
            stop_sniffing()
            break

def stop_sniffing():
    global sniffing
    sniffing = False
    start_stop_button.config(text="Start Sniffing", bg="#006400")

# Save packets to CSV
def save_csv():
    if not packets_list:
        messagebox.showinfo("Info", "No packets to save.")
        return
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        data = []
        for packet_data in packets_list:
            packet = packet_data["packet"]
            src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
            src_mac = packet[Ether].src if packet.haslayer(Ether) else "N/A"
            dst_mac = packet[Ether].dst if packet.haslayer(Ether) else "N/A"
            payload = packet[Raw].load if packet.haslayer(Raw) else b"No Payload"
            data.append([src_ip, dst_ip, packet_data["protocol"], packet_data["timestamp"], len(packet), src_mac, dst_mac, packet.summary(), payload])
        df = pd.DataFrame(data, columns=["Source IP", "Destination IP", "Protocol", "Timestamp", "Frame Size", "Src MAC", "Dst MAC", "Frame Content", "Payload"])
        df.to_csv(filename, index=False)
        messagebox.showinfo("Saved", "Packets saved successfully!")

# Open PCAP file
def open_pcap():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        try:
            packets = rdpcap(file_path)
            packets_list.clear()
            protocol_count.clear()
            tree.delete(*tree.get_children())
            for packet in packets:
                if packet.haslayer(Ether) and (packet.haslayer(IP) or packet.haslayer(ARP)):
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
                    protocol = "Other"
                    if packet.haslayer(TCP):
                        protocol = "HTTP" if packet[TCP].dport == 80 or packet[TCP].sport == 80 else "HTTPS" if packet[TCP].dport == 443 or packet[TCP].sport == 443 else "TCP"
                    elif packet.haslayer(UDP):
                        protocol = "DNS" if packet[UDP].dport == 53 or packet[UDP].sport == 53 else "DHCP" if packet[UDP].dport == 67 or packet[UDP].sport == 68 else "UDP"
                    elif packet.haslayer(ICMP):
                        protocol = "ICMP"
                    elif packet.haslayer(ARP):
                        protocol = "ARP"
                    packet_data = {"packet": packet, "timestamp": timestamp, "protocol": protocol}
                    packets_list.append(packet_data)
                    protocol_count[protocol] += 1
                    src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
                    tree.insert("", "end", values=(len(packets_list), src_ip, dst_ip, protocol, timestamp), tags=(protocol,))
            update_protocol_stats()
            update_graph()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load PCAP: {e}")

# GUI Setup
root = tk.Tk()
root.title("D R A C O  !")
root.geometry("1200x900")
root.configure(bg="#1e1e1e")

# Custom style for Treeview and buttons
style = ttk.Style()
style.theme_use("clam")
style.configure("Dark.Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e", borderwidth=0)
style.map("Dark.Treeview", background=[("selected", "#00ff00")])
style.configure("TCombobox", fieldbackground="#2e2e2e", background="#2e2e2e", foreground="white")

# Automatically select interface
selected_interface = get_default_interface()

# Title and credits (centered)
title_frame = tk.Frame(root, bg="#1e1e1e")
title_frame.pack(side="top", fill="x")
title_label = tk.Label(title_frame, text="D     R     A     C     O     !", font=("Impact", 30), fg="#00ff00", bg="#1e1e1e")
title_label.pack(expand=True, pady=10)
made_by_label = tk.Label(title_frame, text="Made by: Hajredin Husejini \n GitHub: 9hajredin9", font=("Arial", 12), fg="#00ff00", bg="#1e1e1e")
made_by_label.pack(expand=True, pady=5)
start_new_button = tk.Button(title_frame, text="Start New", command=start_new, bg="#39ff14", fg="#1e1e1e", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
start_new_button.pack(side="right", padx=10, pady=5)

# Traffic filter (capture filter)
tk.Label(root, text="Capture Traffic Filter:", font=("Arial", 12), fg="white", bg="#1e1e1e").pack()
traffic_filter_combobox = ttk.Combobox(root, font=("Arial", 12), values=["", "tcp", "udp", "icmp", "arp", "http port 80", "https port 443", "dhcp", "dns port 53"], style="TCombobox")
traffic_filter_combobox.pack()

# Packet filter (display filter)
tk.Label(root, text="Display Packet Filter:", font=("Arial", 12), fg="white", bg="#1e1e1e").pack(pady=5)
packet_filter_combobox = ttk.Combobox(root, font=("Arial", 12), values=["", "TCP", "HTTP", "HTTPS", "UDP", "DNS", "DHCP", "ICMP", "ARP", "Other"], style="TCombobox")
packet_filter_combobox.pack()
packet_filter_combobox.bind("<<ComboboxSelected>>", filter_packets)

# Buttons
button_frame = tk.Frame(root, bg="#1e1e1e")
button_frame.pack(pady=10)
start_stop_button = tk.Button(button_frame, text="Start Sniffing", command=start_stop_sniffing, bg="#006400", fg="white", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
start_stop_button.grid(row=0, column=0, padx=5)
save_btn = tk.Button(button_frame, text="Save CSV", command=save_csv, bg="#00008b", fg="white", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
save_btn.grid(row=0, column=1, padx=5)
open_pcap_btn = tk.Button(button_frame, text="Open PCAP", command=open_pcap, bg="#4b0082", fg="white", font=("Arial", 12, "bold"), relief="flat", padx=10, pady=5)
open_pcap_btn.grid(row=0, column=2, padx=5)

# Main frame for table and graph
main_frame = tk.Frame(root, bg="#1e1e1e")
main_frame.pack(expand=True, fill="both", padx=10, pady=10)

# Packet table
tree_frame = tk.Frame(main_frame, bg="#1e1e1e")
tree_frame.pack(side="left", expand=True, fill="both")
tree = ttk.Treeview(tree_frame, columns=("Row", "Source IP", "Destination IP", "Protocol", "Timestamp"), show="headings", style="Dark.Treeview")
tree.heading("Row", text="Row")
tree.heading("Source IP", text="Source IP")
tree.heading("Destination IP", text="Destination IP")
tree.heading("Protocol", text="Protocol")
tree.heading("Timestamp", text="Timestamp")
tree.tag_configure("TCP", background="#3e4e3e")
tree.tag_configure("HTTP", background="#3e4e3e")
tree.tag_configure("HTTPS", background="#3e4e3e")
tree.tag_configure("UDP", background="#3e3e4e")
tree.tag_configure("DNS", background="#3e3e4e")
tree.tag_configure("DHCP", background="#3e3e4e")
tree.tag_configure("ICMP", background="#4e3e3e")
tree.tag_configure("ARP", background="#4e4e3e")
tree.tag_configure("Other", background="#404040")
tree.pack(side="left", expand=True, fill="both")

tree_scrollbar = tk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
tree_scrollbar.pack(side="right", fill="y")
tree.config(yscrollcommand=tree_scrollbar.set)
tree.bind("<Double-1>", show_packet_details)
tree.bind("<MouseWheel>", lambda e: tree.yview_scroll(int(-1 * (e.delta / 120)), "units"))
tree.bind("<Button-4>", lambda e: tree.yview_scroll(-1, "units"))
tree.bind("<Button-5>", lambda e: tree.yview_scroll(1, "units"))

# Graph
graph_frame = tk.Frame(main_frame, bg="#1e1e1e")
graph_frame.pack(side="right", fill="y", padx=10)
fig, ax = plt.subplots(figsize=(5, 4), dpi=100)
fig.set_facecolor("#1e1e1e")
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack()
update_graph()

# Stats and status
total_packets_label = tk.Label(root, text="Total Packets: 0", font=("Arial", 12), fg="white", bg="#1e1e1e")
total_packets_label.pack(pady=5)
status_label = tk.Label(root, text=f"Status: Stopped on {selected_interface}", font=("Arial", 10, "italic"), fg="#00ff00", bg="#1e1e1e")
status_label.pack(pady=5)

root.mainloop()