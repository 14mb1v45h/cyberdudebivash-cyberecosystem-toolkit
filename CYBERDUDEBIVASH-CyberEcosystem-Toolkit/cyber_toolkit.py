import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import nmap
import requests
import json
import datetime
import os
import threading
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import socket
import shodan
import re
from bs4 import BeautifulSoup
import paramiko

class CyberToolkit:
    def __init__(self, root):
        self.root = root
        self.root.title("CYBERDUDEBIVASH's CyberEcosystem Toolkit")
        self.root.geometry("1000x600")
        self.create_gui()
        self.target = None
        self.report_data = {}

    def create_gui(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(pady=10, expand=True)

        # Tabs
        self.scan_frame = ttk.Frame(self.notebook)
        self.enum_frame = ttk.Frame(self.notebook)
        self.vuln_frame = ttk.Frame(self.notebook)
        self.exploit_frame = ttk.Frame(self.notebook)
        self.report_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.scan_frame, text="Scanning")
        self.notebook.add(self.enum_frame, text="Enumeration")
        self.notebook.add(self.vuln_frame, text="Vulnerability Analysis")
        self.notebook.add(self.exploit_frame, text="Exploitation")
        self.notebook.add(self.report_frame, text="Report Generation")

        # Target Input
        self.target_frame = ttk.LabelFrame(self.root, text="Target")
        self.target_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(self.target_frame, text="Target IP/URL:").grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(self.target_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(self.target_frame, text="Set Target", command=self.set_target).grid(row=0, column=2, padx=5, pady=5)

        # Output Area
        self.output_frame = ttk.LabelFrame(self.root, text="Output")
        self.output_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.output_text = tk.Text(self.output_frame, height=15, width=100)
        self.output_text.pack(padx=5, pady=5)
        self.scrollbar = ttk.Scrollbar(self.output_frame, orient="vertical", command=self.output_text.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.output_text.config(yscrollcommand=self.scrollbar.set)

        # Setup tabs
        self.setup_scan_tab()
        self.setup_enum_tab()
        self.setup_vuln_tab()
        self.setup_exploit_tab()
        self.setup_report_tab()

    def set_target(self):
        self.target = self.target_entry.get().strip()
        if self.target:
            self.output_text.insert(tk.END, f"Target set to: {self.target}\n")
            self.report_data["target"] = self.target
        else:
            messagebox.showerror("Error", "Please enter a valid target.")

    def setup_scan_tab(self):
        ttk.Label(self.scan_frame, text="Network Scanning Options").pack(pady=5)
        self.scan_type = tk.StringVar(value="basic")
        ttk.Radiobutton(self.scan_frame, text="Basic Scan", variable=self.scan_type, value="basic").pack(anchor="w", padx=10)
        ttk.Radiobutton(self.scan_frame, text="Aggressive Scan", variable=self.scan_type, value="aggressive").pack(anchor="w", padx=10)
        ttk.Button(self.scan_frame, text="Run Scan", command=self.run_scan).pack(pady=10)

    def setup_enum_tab(self):
        ttk.Label(self.enum_frame, text="Enumeration Options").pack(pady=5)
        self.enum_type = tk.StringVar(value="ports")
        ttk.Radiobutton(self.enum_frame, text="Port Enumeration", variable=self.enum_type, value="ports").pack(anchor="w", padx=10)
        ttk.Radiobutton(self.enum_frame, text="Service Enumeration", variable=self.enum_type, value="services").pack(anchor="w", padx=10)
        ttk.Button(self.enum_frame, text="Run Enumeration", command=self.run_enumeration).pack(pady=10)

    def setup_vuln_tab(self):
        ttk.Label(self.vuln_frame, text="Vulnerability Analysis Options").pack(pady=5)
        self.vuln_type = tk.StringVar(value="shodan")
        ttk.Radiobutton(self.vuln_frame, text="Shodan Search", variable=self.vuln_type, value="shodan").pack(anchor="w", padx=10)
        ttk.Radiobutton(self.vuln_frame, text="Web Vulnerability Scan", variable=self.vuln_type, value="web").pack(anchor="w", padx=10)
        ttk.Button(self.vuln_frame, text="Run Analysis", command=self.run_vuln_analysis).pack(pady=10)

    def setup_exploit_tab(self):
        ttk.Label(self.exploit_frame, text="Exploitation Options (Ethical Use Only)").pack(pady=5)
        self.exploit_type = tk.StringVar(value="ssh")
        ttk.Radiobutton(self.exploit_frame, text="SSH Brute Force (Demo)", variable=self.exploit_type, value="ssh").pack(anchor="w", padx=10)
        ttk.Radiobutton(self.exploit_frame, text="Web Exploit (Demo)", variable=self.exploit_type, value="web").pack(anchor="w", padx=10)
        ttk.Button(self.exploit_frame, text="Run Exploit", command=self.run_exploit).pack(pady=10)

    def setup_report_tab(self):
        ttk.Label(self.report_frame, text="Report Generation").pack(pady=5)
        ttk.Button(self.report_frame, text="Generate PDF Report", command=self.generate_report).pack(pady=10)

    def run_scan(self):
        if not self.target:
            messagebox.showerror("Error", "Please set a target first.")
            return
        threading.Thread(target=self.perform_scan, daemon=True).start()

    def perform_scan(self):
        self.output_text.insert(tk.END, "Starting network scan...\n")
        nm = nmap.PortScanner()
        scan_args = "-sS" if self.scan_type.get() == "basic" else "-A"
        try:
            nm.scan(self.target, arguments=scan_args)
            scan_results = nm.all_hosts()
            self.report_data["scan_results"] = nm.csv()
            for host in scan_results:
                self.output_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        self.output_text.insert(tk.END, f"Port: {port}\tState: {nm[host][proto][port]['state']}\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"Scan error: {str(e)}\n")

    def run_enumeration(self):
        if not self.target:
            messagebox.showerror("Error", "Please set a target first.")
            return
        threading.Thread(target=self.perform_enumeration, daemon=True).start()

    def perform_enumeration(self):
        self.output_text.insert(tk.END, "Starting enumeration...\n")
        try:
            if self.enum_type.get() == "ports":
                nm = nmap.PortScanner()
                nm.scan(self.target, arguments="-p-")
                ports = []
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        ports.extend(nm[host][proto].keys())
                self.output_text.insert(tk.END, f"Open ports: {ports}\n")
                self.report_data["enum_ports"] = ports
            else:
                nm = nmap.PortScanner()
                nm.scan(self.target, arguments="-sV")
                services = []
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto]:
                            services.append(nm[host][proto][port]['name'])
                self.output_text.insert(tk.END, f"Services: {services}\n")
                self.report_data["enum_services"] = services
        except Exception as e:
            self.output_text.insert(tk.END, f"Enumeration error: {str(e)}\n")

    def run_vuln_analysis(self):
        if not self.target:
            messagebox.showerror("Error", "Please set a target first.")
            return
        threading.Thread(target=self.perform_vuln_analysis, daemon=True).start()

    def perform_vuln_analysis(self):
        self.output_text.insert(tk.END, "Starting vulnerability analysis...\n")
        try:
            if self.vuln_type.get() == "shodan":
                api_key = os.getenv("SHODAN_API_KEY")  # Set your Shodan API key in environment
                if not api_key:
                    self.output_text.insert(tk.END, "Shodan API key not set.\n")
                    return
                api = shodan.Shodan(api_key)
                results = api.host(self.target)
                self.output_text.insert(tk.END, f"OS: {results.get('os', 'Unknown')}\n")
                self.output_text.insert(tk.END, f"Ports: {results.get('ports', [])}\n")
                self.report_data["vuln_shodan"] = results
            else:
                response = requests.get(f"http://{self.target}", timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                self.output_text.insert(tk.END, f"Found {len(forms)} forms on webpage.\n")
                self.report_data["vuln_web"] = {"forms_count": len(forms)}
        except Exception as e:
            self.output_text.insert(tk.END, f"Vulnerability analysis error: {str(e)}\n")

    def run_exploit(self):
        if not self.target:
            messagebox.showerror("Error", "Please set a target first.")
            return
        threading.Thread(target=self.perform_exploit, daemon=True).start()

    def perform_exploit(self):
        self.output_text.insert(tk.END, "Starting exploitation (demo mode)...\n")
        try:
            if self.exploit_type.get() == "ssh":
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(self.target, username="test", password="test", timeout=5)
                    self.output_text.insert(tk.END, "SSH connection successful (demo).\n")
                except:
                    self.output_text.insert(tk.END, "SSH connection failed (demo).\n")
                self.report_data["exploit_ssh"] = "Demo SSH attempt"
            else:
                self.output_text.insert(tk.END, "Web exploit not implemented in demo mode.\n")
                self.report_data["exploit_web"] = "Demo web exploit"
        except Exception as e:
            self.output_text.insert(tk.END, f"Exploitation error: {str(e)}\n")

    def generate_report(self):
        if not self.report_data:
            messagebox.showerror("Error", "No data to generate report.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if file_path:
            threading.Thread(target=self.create_pdf_report, args=(file_path,), daemon=True).start()

    def create_pdf_report(self, file_path):
        c = canvas.Canvas(file_path, pagesize=letter)
        c.drawString(100, 750, "CYBERDUDEBIVASH's CyberEcosystem Toolkit Report")
        c.drawString(100, 730, f"Target: {self.report_data.get('target', 'Unknown')}")
        c.drawString(100, 710, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y = 690
        for key, value in self.report_data.items():
            if key != "target":
                c.drawString(100, y, f"{key.replace('_', ' ').title()}:")
                y -= 20
                c.drawString(120, y, str(value)[:100] + "..." if len(str(value)) > 100 else str(value))
                y -= 20
        c.showPage()
        c.save()
        self.output_text.insert(tk.END, f"Report saved to {file_path}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberToolkit(root)
    root.mainloop()