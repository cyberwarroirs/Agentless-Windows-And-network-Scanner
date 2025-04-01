from flask import Flask, render_template, request, redirect, url_for, flash
import PyPDF2
import re
import asyncio
import aiohttp
import os

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "your_default_secret_key")  # Use environment variable or default

# Extract URLs or domain-like text from the PDF
def extract_urls_from_pdf(pdf_file):
    try:
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            page_text = page.extract_text()
            text += page_text or ""  # Handle None if page text is None
            print(f"Extracted text from page {page_num}: {page_text}")  # Debug print for each page text

        # Refine regex to capture subdomains (e.g., sub.example.com or *.example.com)
        urls = re.findall(r'(?:(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\*\.)[a-zA-Z0-9-]+\.[a-zA-Z]{2,})', text)
        # Replace wildcard domains and convert to HTTP URL format
        return [url.replace('*.', 'http://') if url.startswith('*.') else f"http://{url}" for url in urls]
    except Exception as e:
        print(f"Error extracting URLs from PDF: {str(e)}")
        return []

# Asynchronous check if subdomains are live
async def check_subdomain_live(session, subdomain):
    try:
        async with session.get(subdomain, timeout=5) as response:  # Increased timeout for reliability
            print(f"Checking: {subdomain}, Status Code: {response.status}")
            return response.status == 200
    except Exception as e:
        print(f"Failed to reach: {subdomain}, Error: {str(e)}")
        return False

async def check_live_subdomains(subdomains):
    async with aiohttp.ClientSession() as session:
        tasks = [check_subdomain_live(session, url) for url in subdomains]
        return await asyncio.gather(*tasks)

@app.route('/')
def index():
    return render_template('index4.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'pdf' not in request.files:
        flash("No file uploaded!", "error")
        return redirect(url_for('index'))

    pdf_file = request.files['pdf']

    # Ensure that the uploaded file is a PDF by checking both the extension and MIME type
    if not pdf_file.filename.endswith('.pdf') or pdf_file.mimetype != 'application/pdf':
        flash("Uploaded file is not a valid PDF!", "error")
        return redirect(url_for('index'))

    # Extract URLs from the PDF
    urls = extract_urls_from_pdf(pdf_file)

    # Debug: Print the extracted URLs
    print("Extracted URLs:", urls)

    # Check which URLs (subdomains) are live asynchronously
    live_subdomains = []
    if urls:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        live_statuses = loop.run_until_complete(check_live_subdomains(urls))

        # Filter the live subdomains
        live_subdomains = [url for url, is_live in zip(urls, live_statuses) if is_live]
        
        # Debug: Print the live subdomains
        print("Live Subdomains:", live_subdomains)

    # Provide feedback if no live subdomains found
    if not live_subdomains:
        flash("No live subdomains found in the uploaded PDF.", "info")

    # Render the index page with the list of live subdomains
    return render_template('index4.html', live_subdomains=live_subdomains)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=True)
