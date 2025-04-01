from flask import Flask, render_template, request, send_file,redirect, url_for
import requests
import socket
import whois
import json
import os
from fpdf import FPDF

app = Flask(__name__)

# Functions from your script
def get_subdomains(domain):
    subdomains = []
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if response.status_code == 200:
            subdomain_data = response.json()
            subdomains = list(set([entry['name_value'] for entry in subdomain_data]))
    except Exception as e:
        print(f"Error gathering subdomains: {e}")
    return subdomains

def get_dns_info(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        print(f"DNS lookup failed: {e}")
        return None

def get_http_headers(domain):
    try:
        return requests.get(f"http://{domain}").headers
    except requests.RequestException as e:
        print(f"HTTP request failed: {e}")
        return {}

def security_audit(headers):
    vulnerabilities = []
    if 'Server' in headers and "Apache/2.4.7" in headers['Server']:
        vulnerabilities.append("Outdated Apache server detected.")
    if 'X-Frame-Options' not in headers:
        vulnerabilities.append("X-Frame-Options header missing.")
    if 'X-XSS-Protection' not in headers:
        vulnerabilities.append("X-XSS-Protection header missing.")
    if 'Strict-Transport-Security' not in headers:
        vulnerabilities.append("Strict-Transport-Security header missing.")
    return vulnerabilities

def create_pdf_report(domain_info, dns_info, headers, audit_results, subdomains):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, 'Security Audit Report', 0, 1, 'C')
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Domain Info', 0, 1)
    pdf.set_font("Arial", '', 12)
    pdf.multi_cell(0, 10, domain_info)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'DNS Info', 0, 1)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 10, f'IP Address: {dns_info}', 0, 1)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'HTTP Headers', 0, 1)
    pdf.set_font("Arial", '', 12)
    for header, value in headers.items():
        pdf.cell(0, 10, f'{header}: {value}', 0, 1)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Security Audit', 0, 1)
    pdf.set_font("Arial", '', 12)
    for vulnerability in audit_results:
        pdf.cell(0, 10, f'- {vulnerability}', 0, 1)
    pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, 'Subdomains', 0, 1)
    pdf.set_font("Arial", '', 12)
    for subdomain in subdomains:
        pdf.cell(0, 10, subdomain, 0, 1)

    # Save the PDF
    pdf_file_path = 'report.pdf'
    pdf.output(pdf_file_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain'].strip().replace('http://', '').replace('https://', '').split('/')[0]
        
        subdomains = get_subdomains(domain)
        try:
            domain_info = whois.whois(domain)
            domain_info = json.dumps(domain_info, indent=2, default=str)
        except Exception as e:
            domain_info = f"WHOIS lookup failed: {e}"

        dns_info = get_dns_info(domain)
        headers = get_http_headers(domain)
        audit_results = security_audit(headers)

        # Generate the PDF report
        create_pdf_report(domain_info, dns_info, headers, audit_results, subdomains)

        return render_template('index2.html', 
                               subdomains=subdomains, 
                               domain_info=domain_info,
                               dns_info=dns_info, 
                               headers=headers,
                               audit_results=audit_results)
    return render_template('index2.html')

@app.route('/download_report')
def download_report():
    file_path = 'report.pdf'
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "Report not found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
