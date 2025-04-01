from flask import Flask, render_template, request, send_file, redirect
import nmap
from threading import Thread
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import subprocess

app = Flask(__name__)

scan_results = {}
report_filename = "scan_report.pdf"

# Function to run Nmap scan
def run_nmap_scan(target, scan_type):
    global scan_results
    scan_results = {}
    scan_results['message'] = f"Scanning {target} with {scan_type} scan...\n"

    scanner = nmap.PortScanner()

    try:
        scan_args = {
            'port': '-p- -T4 -sV -sC',
            'host': '-sP -PS -PA -T4',
            'ping': '-sn',
            'os': '-O -sV -T4',
            'dns': '-p 53 --script "(dns-brute,dns-nsid,dns-zone-transfer,dns-recursion,dns-service-discovery)" -T4',
            'full': '-p- -T4 -sV -sC -O --script vuln'
        }.get(scan_type, '')

        scanner.scan(hosts=target, arguments=scan_args)

        for host in scanner.all_hosts():
            scan_results[host] = {
                'hostname': scanner[host].hostname(),
                'state': scanner[host].state(),
                'os': {},
                'details': {'ports': []}
            }

            for proto in scanner[host].all_protocols():
                for port, data in scanner[host][proto].items():
                    scan_results[host]['details']['ports'].append({
                        'port': port,
                        'state': data["state"],
                        'service': data.get("name", "Unknown"),
                        'product': data.get("product", "N/A"),
                        'version': data.get("version", "N/A"),
                        'cpe': data.get("cpe", "N/A")
                    })

        create_pdf_report(target, scan_type)

    except Exception as e:
        scan_results['message'] = f"Error scanning {target}: {str(e)}"

# Function to create PDF Report
def create_pdf_report(target, scan_type):
    c = canvas.Canvas(report_filename, pagesize=letter)
    c.drawString(72, 720, "The End Is Beginning!")
    c.drawString(72, 700, f"Scan Target: {target}")
    c.drawString(72, 680, f"Scan Type: {scan_type}")
    c.drawString(72, 660, "Scan Results:")

    y = 640
    for host, result in scan_results.items():
        if host == 'message':
            continue
        c.drawString(72, y, f"Host: {host} - State: {result['state']}")
        y -= 20
        for port in result['details']['ports']:
            c.drawString(72, y, f"Port: {port['port']} - State: {port['state']} - Service: {port['service']} - Product: {port['product']} - Version: {port['version']} - CPE: {port['cpe']}")
            y -= 20
        y -= 10

    c.save()

# Function to start all apps in subprocesses
def start_apps():
    subprocess.Popen(["python", "apps/app1.py"])
    subprocess.Popen(["python", "apps/app2.py"])
    subprocess.Popen(["python", "apps/app3.py"])
    subprocess.Popen(["python", "apps/app4.py"])
    subprocess.Popen(["python", "apps/app5.py"])

@app.route('/', methods=['GET', 'POST'])
def index():
    global scan_results

    if request.method == 'POST':
        target = request.form['target']
        scan_type = request.form['scan_type']

        scan_thread = Thread(target=run_nmap_scan, args=(target, scan_type))
        scan_thread.start()
        scan_thread.join()

        return render_template('index.html', scan_results=scan_results, report_available=True)
    
    return render_template('index.html', scan_results=scan_results, report_available=False)

# Routes for different tools
@app.route('/run_security_audit', methods=['GET'])
def run_security_audit():
    subprocess.Popen(["python", "apps/app1.py"])
    return redirect("http://127.0.0.1:5001/")

@app.route('/run_live_subdomain_finder', methods=['GET'])
def run_live_subdomain_finder():
    subprocess.Popen(["python", "apps/app2.py"])
    return redirect("http://127.0.0.1:5002/")

@app.route('/run_subdomain_finder', methods=['GET'])
def run_subdomain_finder():
    subprocess.Popen(["python", "apps/app3.py"])
    return redirect("http://127.0.0.1:5003/")

@app.route('/download')
def download_report():
    return send_file(report_filename, as_attachment=True)

if __name__ == '__main__':
    # Start all apps when the main app runs
    start_apps()

    # Start the main app (this will keep it running)
    app.run(host="0.0.0.0", port=5000, debug=True)
