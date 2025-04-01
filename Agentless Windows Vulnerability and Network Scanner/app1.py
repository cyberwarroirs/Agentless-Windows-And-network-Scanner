from flask import Flask, render_template, request, Response
import wmi
import pythoncom
import psutil
import socket
from fpdf import FPDF

app = Flask(__name__)

scan_results = ""  # To store scan results

def initialize_wmi():
    pythoncom.CoInitialize()
    return wmi.WMI()

def check_firewall_status(wmi_conn):
    report = "[*] Checking Windows Firewall status...\n"
    try:
        firewall = wmi_conn.Win32_Service(Name="MpsSvc")[0]
        if firewall.StartMode == "Auto" and firewall.State == "Running":
            report += "[+] Windows Firewall is enabled.\n"
        else:
            report += "[-] Windows Firewall is disabled.\n"
    except Exception as e:
        report += f"[-] Error while checking firewall status: {e}\n"
    return report

def check_suspicious_software(wmi_conn):
    report = "[*] Checking for suspicious software...\n"
    try:
        suspicious_keywords = ["hacker", "crack", "trojan", "backdoor", "exploit"]
        for software in wmi_conn.Win32_Product():
            if software.Name and any(keyword in software.Name.lower() for keyword in suspicious_keywords):
                report += f"[-] Suspicious software detected: {software.Name}\n"
    except Exception as e:
        report += f"[-] Error while checking suspicious software: {e}\n"
    return report

def get_open_ports():
    report = "[*] Checking open ports...\n"
    try:
        for conn in psutil.net_connections():
            if conn.status == "LISTEN":
                report += f"[+] Port {conn.laddr.port} is open (Process: {conn.pid})\n"
    except Exception as e:
        report += f"[-] Error while checking open ports: {e}\n"
    return report

def get_network_connections():
    report = "[*] Checking network connections...\n"
    try:
        for interface, addresses in psutil.net_if_addrs().items():
            report += f"[+] Interface {interface}:\n"
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    report += f"  - IP Address: {addr.address}\n"
                elif addr.family == socket.AF_INET6:
                    report += f"  - IPv6 Address: {addr.address}\n"
    except Exception as e:
        report += f"[-] Error while checking network connections: {e}\n"
    return report

def get_disk_usage():
    report = "[*] Checking hard disk usage...\n"
    try:
        partitions = psutil.disk_partitions()
        for partition in partitions:
            usage = psutil.disk_usage(partition.mountpoint)
            report += (f"[+] Partition {partition.mountpoint}: "
                       f"Total: {usage.total / (1024 ** 3):.2f} GB, "
                       f"Used: {usage.used / (1024 ** 3):.2f} GB, "
                       f"Free: {usage.free / (1024 ** 3):.2f} GB, "
                       f"Percentage: {usage.percent}%\n")
    except Exception as e:
        report += f"[-] Error while checking disk usage: {e}\n"
    return report

@app.route("/", methods=["GET"])
def index():
    return render_template("index1.html", scan_results=None)

@app.route("/scan", methods=["POST"])
def scan():
    global scan_results
    # Initialize WMI connection
    wmi_conn = initialize_wmi()

    # Perform security checks
    scan_results = ""
    scan_results += check_firewall_status(wmi_conn)
    scan_results += check_suspicious_software(wmi_conn)
    scan_results += get_open_ports()
    scan_results += get_network_connections()
    scan_results += get_disk_usage()

    return render_template("index1.html", scan_results=scan_results)

@app.route("/download_report", methods=["POST"])
def download_report():
    global scan_results

    # Generate PDF using FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Local System Vulnerability", 0, 1, "C")
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    for line in scan_results.splitlines():
        pdf.cell(0, 10, line, 0, 1)

    # Create PDF response
    response = Response(pdf.output(dest='S').encode('latin1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
