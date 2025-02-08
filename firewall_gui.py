import tkinter as tk
from tkinter import messagebox
import firewall  # Import the firewall script

def add_ip():
    ip = ip_entry.get()
    if ip:
        firewall.BLOCKED_IPS.append(ip)
        ip_listbox.insert(tk.END, ip)
        ip_entry.delete(0, tk.END)

def add_port():
    port = port_entry.get()
    if port.isdigit():
        firewall.BLOCKED_PORTS.append(int(port))
        port_listbox.insert(tk.END, port)
        port_entry.delete(0, tk.END)

def start_firewall():
    messagebox.showinfo("Firewall", "Firewall is now running! Check console for logs.")
    firewall.sniff(prn=firewall.packet_callback, store=0)

app = tk.Tk()
app.title("🔥 Advanced Firewall Configuration")

tk.Label(app, text="Block IP:").grid(row=0, column=0)
ip_entry = tk.Entry(app)
ip_entry.grid(row=0, column=1)
tk.Button(app, text="Add", command=add_ip).grid(row=0, column=2)

tk.Label(app, text="Blocked IPs:").grid(row=1, column=0)
ip_listbox = tk.Listbox(app)
ip_listbox.grid(row=1, column=1, columnspan=2)

tk.Label(app, text="Block Port:").grid(row=2, column=0)
port_entry = tk.Entry(app)
port_entry.grid(row=2, column=1)
tk.Button(app, text="Add", command=add_port).grid(row=2, column=2)

tk.Label(app, text="Blocked Ports:").grid(row=3, column=0)
port_listbox = tk.Listbox(app)
port_listbox.grid(row=3, column=1, columnspan=2)

tk.Button(app, text="Start Firewall", command=start_firewall).grid(row=4, column=0, columnspan=3)

app.mainloop()

