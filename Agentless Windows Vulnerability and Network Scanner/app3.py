from flask import Flask, render_template, request, make_response, redirect, url_for
import dns.resolver
import requests
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

app = Flask(__name__)

VT_API_KEY = '447b1bc9d43ba65301effae159669eda66e991e3a1cb80a5cecc2dd4bcf6bbbf'

# Function to check for subdomains using DNS resolver
def find_subdomains_bruteforce(domain):
    found_subdomains = []
    with open('subdomains.txt', 'r') as file:
        subdomains = file.read().splitlines()
    for subdomain in subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            dns.resolver.resolve(full_domain, 'A')
            found_subdomains.append(full_domain)
        except dns.resolver.NXDOMAIN:
            continue
        except Exception as e:
            print(f"Error resolving {full_domain}: {e}")
            continue
    return found_subdomains

# Function to fetch subdomains from VirusTotal API
def find_subdomains_virustotal(domain):
    subdomains = []
    if VT_API_KEY:
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={VT_API_KEY}&domain={domain}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])
    return subdomains

# Function to find subdomains using Certificate Transparency logs
def find_subdomains_cert_transparency(domain):
    subdomains = []
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if response.status_code == 200:
            entries = response.json()
            subdomains = list(set(entry['name_value'] for entry in entries))
    except Exception as e:
        print(f"Error fetching data from Certificate Transparency logs: {e}")
    return subdomains

# Main route (Form Page)
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        # Redirect to the results page
        return redirect(url_for('results', domain=domain))
    return render_template('index3.html')

# Results Page (after submission)
@app.route('/results', methods=['GET'])
def results():
    domain = request.args.get('domain')
    subdomains_bruteforce = find_subdomains_bruteforce(domain)
    subdomains_virustotal = find_subdomains_virustotal(domain)
    subdomains_cert_transparency = find_subdomains_cert_transparency(domain)
    
    # Remove duplicates by converting to a set, then sort and join with line breaks
    subdomains = set(subdomains_bruteforce + subdomains_virustotal + subdomains_cert_transparency)
    sorted_subdomains = sorted(subdomains)
    formatted_subdomains = "\n".join(sorted_subdomains)
    
    return render_template('index3.html', domain=domain, subdomains=formatted_subdomains)

@app.route('/download/pdf', methods=['GET'])
def download_pdf():
    domain = request.args.get('domain')
    if not domain:
        return "Domain not provided", 400

    # Fetch subdomains from different sources
    subdomains_bruteforce = find_subdomains_bruteforce(domain)
    subdomains_virustotal = find_subdomains_virustotal(domain)
    subdomains_cert_transparency = find_subdomains_cert_transparency(domain)

    # Combine all subdomains and remove duplicates
    subdomains = set(subdomains_bruteforce + subdomains_virustotal + subdomains_cert_transparency)

    # Filter out unwanted characters and fix concatenated subdomains
    filtered_subdomains = [
        sub.replace('■', '\n').strip() for sub in subdomains if '*' not in sub and 'box' not in sub
    ]
    
    # Sort the filtered subdomains
    sorted_subdomains = sorted(filtered_subdomains)

    # Create a PDF file
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    # Set initial position for text
    x = 50
    y = 750  # Start from the top of the page
    count = 0

    # Add title and separator
    pdf.setFont("Helvetica", 12)
    pdf.drawString(x, y, f"Subdomain Enumeration Report for {domain}")
    y -= 20
    pdf.drawString(x, y, "--------------------------------------------------------")
    y -= 20

    # Write each subdomain on a new line
    for subdomain in sorted_subdomains:
        # Split subdomains by new line and write each separately
        for line in subdomain.split('\n'):
            pdf.drawString(x, y, line)
            y -= 20
            count += 1

            # Start a new page after 40 subdomains
            if count == 40:
                pdf.showPage()
                pdf.setFont("Helvetica", 12)
                y = 750
                count = 0
    
    # Finalize and save the PDF
    pdf.save()

    # Return PDF as a response
    buffer.seek(0)
    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=subdomain_report_{domain}.pdf'
    return response



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)